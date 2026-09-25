package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// otelState is an immutable snapshot of the global tracing state. The
// per-connection hot path loads exactly one snapshot per lookup, so the tracer
// and its active flag can never be observed in a torn combination
// (SPEC-OTEL-007 / INV-OTEL-C1).
type otelState struct {
	tracer trace.Tracer
	active bool
}

var (
	noopState            = otelState{tracer: noop.NewTracerProvider().Tracer("vproxy")}
	globalState          atomic.Pointer[otelState]
	globalTracerProvider *sdktrace.TracerProvider
	globalOtelConfig     *OtelConfig
	// globalTracerMu serializes writers (init/shutdown) only. The hot path never
	// acquires it, so a slow writer cannot stall connection handling
	// (INV-OTEL-C3).
	globalTracerMu sync.Mutex
)

func noopTracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("vproxy")
}

// currentState returns the published snapshot, falling back to a no-op snapshot
// before the first InitOtelTracer call.
func currentState() *otelState {
	if s := globalState.Load(); s != nil {
		return s
	}
	return &noopState
}

// buildOtelProvider constructs a TracerProvider from cfg. A nil or disabled cfg
// yields (nil, noopTracer, nil). It never mutates global state, so a failure
// leaves the previously published configuration fully intact (INV-OTEL-C2).
func buildOtelProvider(ctx context.Context, cfg *OtelConfig) (*sdktrace.TracerProvider, trace.Tracer, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, noopTracer(), nil
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "localhost:4317"
	}
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "vproxy"
	}

	var client otlptrace.Client
	protocol := strings.ToLower(cfg.Protocol)
	if protocol == "http" {
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		client = otlptracehttp.NewClient(opts...)
	} else {
		// Default to gRPC
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		client = otlptracegrpc.NewClient(opts...)
	}

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			attribute.String("service.version", "1.0.7"),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create otel resource: %w", err)
	}

	sampleRate := cfg.SampleRate
	if sampleRate <= 0 {
		sampleRate = 1.0
	}

	var sampler sdktrace.Sampler
	if sampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(sampleRate)
	}

	bsp := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithBatchTimeout(2*time.Second),
		sdktrace.WithMaxExportBatchSize(512),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	return tp, tp.Tracer(serviceName), nil
}

func copyOtelConfig(cfg *OtelConfig) *OtelConfig {
	if cfg == nil {
		return nil
	}
	c := *cfg
	return &c
}

func otelConfigEqual(a, b *OtelConfig) bool {
	aEnabled := a != nil && a.Enabled
	bEnabled := b != nil && b.Enabled
	if !aEnabled && !bEnabled {
		return true
	}
	if aEnabled != bEnabled {
		return false
	}

	aEndpoint := a.Endpoint
	if aEndpoint == "" {
		aEndpoint = "localhost:4317"
	}
	bEndpoint := b.Endpoint
	if bEndpoint == "" {
		bEndpoint = "localhost:4317"
	}

	aProto := strings.ToLower(a.Protocol)
	if aProto == "" {
		aProto = "grpc"
	}
	bProto := strings.ToLower(b.Protocol)
	if bProto == "" {
		bProto = "grpc"
	}

	aService := a.ServiceName
	if aService == "" {
		aService = "vproxy"
	}
	bService := b.ServiceName
	if bService == "" {
		bService = "vproxy"
	}

	aRate := a.SampleRate
	if aRate <= 0 {
		aRate = 1.0
	}
	bRate := b.SampleRate
	if bRate <= 0 {
		bRate = 1.0
	}

	return aEndpoint == bEndpoint &&
		aProto == bProto &&
		a.Insecure == b.Insecure &&
		aService == bService &&
		aRate == bRate
}

func makeShutdown() func(context.Context) error {
	return func(shutdownCtx context.Context) error {
		globalTracerMu.Lock()
		old := globalTracerProvider
		globalTracerProvider = nil
		globalOtelConfig = nil
		globalState.Store(&noopState)
		globalTracerMu.Unlock()
		return shutdownProvider(shutdownCtx, old)
	}
}

// InitOtelTracer initializes the OpenTelemetry TracerProvider according to
// OtelConfig. If cfg is nil or not enabled, a noop tracer is used.
//
// Ordering follows SPEC-OTEL-007: the new snapshot is published atomically
// before the previous provider is torn down, and that teardown happens outside
// globalTracerMu so a hanging collector can never block the hot path.
func InitOtelTracer(ctx context.Context, cfg *OtelConfig) (func(context.Context) error, error) {
	globalTracerMu.Lock()

	// If the config has not changed, do not rebuild exporter or interrupt active spans.
	if otelConfigEqual(globalOtelConfig, cfg) {
		globalTracerMu.Unlock()
		if cfg == nil || !cfg.Enabled {
			return func(context.Context) error { return nil }, nil
		}
		return makeShutdown(), nil
	}

	tp, tracer, err := buildOtelProvider(ctx, cfg)
	if err != nil {
		// INV-OTEL-C2: keep the previously published snapshot untouched.
		globalTracerMu.Unlock()
		return nil, err
	}

	if tp != nil {
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
	}

	old := globalTracerProvider
	globalTracerProvider = tp
	globalOtelConfig = copyOtelConfig(cfg)
	globalState.Store(&otelState{tracer: tracer, active: tp != nil})
	globalTracerMu.Unlock()

	// INV-OTEL-C3: publish first, then tear down the previous provider unlocked.
	_ = shutdownProvider(ctx, old)

	if tp == nil {
		return func(context.Context) error { return nil }, nil
	}

	return makeShutdown(), nil
}

// shutdownProvider closes a provider that has already been detached from the
// global state. Callers must not hold globalTracerMu (INV-OTEL-C3).
func shutdownProvider(ctx context.Context, tp *sdktrace.TracerProvider) error {
	if tp == nil {
		return nil
	}
	shutdownCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	return tp.Shutdown(shutdownCtx)
}

// IsOtelActive returns true if OpenTelemetry tracing is enabled and running.
func IsOtelActive() bool {
	return currentState().active
}

// GetOtelTracer returns the active OTel tracer or a noop tracer.
func GetOtelTracer() trace.Tracer {
	return currentState().tracer
}
