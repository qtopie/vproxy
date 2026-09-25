package internal

import (
	"context"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// isNoopTracer reports whether tracer is the no-op tracer published when OTel is
// inactive.
func isNoopTracer(tracer trace.Tracer) bool {
	return reflect.TypeOf(tracer) == reflect.TypeOf(noopTracer())
}

func TestOtelLifecycleAndConfig(t *testing.T) {
	// 1. Disabled by default or nil
	shutdown, err := InitOtelTracer(context.Background(), nil)
	if err != nil {
		t.Fatalf("InitOtelTracer with nil config failed: %v", err)
	}
	if IsOtelActive() {
		t.Errorf("Expected IsOtelActive() == false for nil config")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}

	// 2. Disabled explicitly
	cfg := &OtelConfig{Enabled: false}
	shutdown, err = InitOtelTracer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("InitOtelTracer disabled config failed: %v", err)
	}
	if IsOtelActive() {
		t.Errorf("Expected IsOtelActive() == false for disabled config")
	}
	_ = shutdown(context.Background())
}

func TestOtelSpanHierarchyAndAttributes(t *testing.T) {
	// Setup in-memory exporter
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("vproxy-test")

	ctx, sessionSpan := tracer.Start(context.Background(), "vproxy.session",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("net.transport", "tcp"),
			attribute.String("client.address", "127.0.0.1"),
			attribute.Int("client.port", 54321),
			attribute.String("destination.address", "google.com"),
			attribute.Int("destination.port", 443),
			attribute.Int("process.pid", 12345),
			attribute.String("process.executable.name", "curl"),
		),
	)

	// Child span: vproxy.route
	_, routeSpan := tracer.Start(ctx, "vproxy.route",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("rule.type", "PROCESS"),
			attribute.String("rule.action", "PROXY"),
			attribute.String("dns.resolved_host", "google.com"),
		),
	)
	routeSpan.End()

	// Child span: vproxy.upstream_dial
	_, dialSpan := tracer.Start(ctx, "vproxy.upstream_dial",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("upstream.address", "socks5://192.168.50.189:1080"),
			attribute.Int("dial.attempt", 1),
		),
	)
	dialSpan.End()

	// Child span: vproxy.relay
	_, relaySpan := tracer.Start(ctx, "vproxy.relay",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.Int64("traffic.bytes_sent", 1024),
			attribute.Int64("traffic.bytes_received", 4096),
		),
	)
	relaySpan.End()

	sessionSpan.End()

	spans := exporter.GetSpans()
	if len(spans) != 4 {
		t.Fatalf("expected 4 spans, got %d", len(spans))
	}

	spanMap := make(map[string]tracetest.SpanStub)
	for _, s := range spans {
		spanMap[s.Name] = s
	}

	session, ok := spanMap["vproxy.session"]
	if !ok {
		t.Fatalf("vproxy.session span not found")
	}

	// Verify parent-child relations
	for _, name := range []string{"vproxy.route", "vproxy.upstream_dial", "vproxy.relay"} {
		child, exists := spanMap[name]
		if !exists {
			t.Fatalf("span %s not found", name)
		}
		if child.Parent.SpanID() != session.SpanContext.SpanID() {
			t.Errorf("span %s has parent %s, want %s", name, child.Parent.SpanID(), session.SpanContext.SpanID())
		}
	}

	// Verify session span attributes
	attrMap := make(map[string]interface{})
	for _, a := range session.Attributes {
		attrMap[string(a.Key)] = a.Value.AsInterface()
	}

	if attrMap["process.pid"] != int64(12345) {
		t.Errorf("expected process.pid == 12345, got %v", attrMap["process.pid"])
	}
	if attrMap["process.executable.name"] != "curl" {
		t.Errorf("expected process.executable.name == curl, got %v", attrMap["process.executable.name"])
	}
}

// TestOtelStateSnapshotConsistency verifies SPEC-OTEL-007 / INV-OTEL-C1: the
// tracer and its active flag are published as one immutable snapshot, so a
// reader can never observe a torn combination.
func TestOtelStateSnapshotConsistency(t *testing.T) {
	if s := currentState(); s.tracer == nil || s.active {
		t.Fatalf("default snapshot must be a non-nil, inactive tracer")
	}

	cfg := &OtelConfig{Enabled: true, Endpoint: "127.0.0.1:1", Protocol: "grpc", Insecure: true, ServiceName: "vproxy-test"}
	shutdown, err := InitOtelTracer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("InitOtelTracer failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	s := currentState()
	if !s.active {
		t.Errorf("snapshot must be active after a successful init")
	}
	if isNoopTracer(s.tracer) {
		t.Errorf("an active snapshot must not carry the noop tracer")
	}
	if !IsOtelActive() || GetOtelTracer() == nil {
		t.Errorf("public accessors disagree with the published snapshot")
	}
}

// TestOtelInitFailureKeepsState verifies SPEC-OTEL-007 / INV-OTEL-C2: a failed
// rebuild must leave the previously published snapshot intact and must not leave
// the writer lock held.
func TestOtelInitFailureKeepsState(t *testing.T) {
	cfg := &OtelConfig{Enabled: true, Endpoint: "127.0.0.1:1", Protocol: "grpc", Insecure: true, ServiceName: "vproxy-test", SampleRate: 0}
	shutdown, err := InitOtelTracer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("baseline InitOtelTracer failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// An already-canceled context makes the OTLP HTTP exporter construction
	// fail deterministically (the gRPC client dials lazily and tolerates it).
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	failing := &OtelConfig{Enabled: true, Endpoint: "127.0.0.1:1", Protocol: "http", Insecure: true, ServiceName: "vproxy-test", SampleRate: 0}
	if _, err := InitOtelTracer(canceled, failing); err == nil {
		t.Fatalf("expected InitOtelTracer with a canceled context to fail")
	}

	if !IsOtelActive() || isNoopTracer(GetOtelTracer()) {
		t.Fatalf("INV-OTEL-C2 violated: previous snapshot was downgraded by a failed init")
	}

	// The writer lock must have been released: a later init must still complete.
	done := make(chan error, 1)
	go func() {
		_, err := InitOtelTracer(context.Background(), &OtelConfig{Enabled: false})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("InitOtelTracer after a failed init returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("InitOtelTracer deadlocked after a failed init")
	}
}

// TestOtelConcurrentStateAccess is the regression test for SPEC-OTEL-007
// (INV-OTEL-C1/C4): hot-path reads racing init/shutdown must observe a
// consistent (tracer, active) pair and must be free of data races under
// `go test -race`.
func TestOtelConcurrentStateAccess(t *testing.T) {
	enabled := &OtelConfig{Enabled: true, Endpoint: "127.0.0.1:1", Protocol: "grpc", Insecure: true, ServiceName: "vproxy-race", SampleRate: 0}
	disabled := &OtelConfig{Enabled: false}

	const readers = 8
	const iterations = 100

	var torn, nilTracer int64
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := currentState()
				if s.tracer == nil {
					atomic.AddInt64(&nilTracer, 1)
					continue
				}
				// active must pair with a real tracer, and vice versa.
				if s.active == isNoopTracer(s.tracer) {
					atomic.AddInt64(&torn, 1)
				}
				if GetOtelTracer() == nil {
					atomic.AddInt64(&nilTracer, 1)
				}
				_ = IsOtelActive()
			}
		}()
	}

	for i := 0; i < iterations; i++ {
		shutdown, err := InitOtelTracer(context.Background(), enabled)
		if err != nil {
			t.Errorf("InitOtelTracer(enabled) failed: %v", err)
			break
		}
		_ = shutdown(context.Background())
		if _, err := InitOtelTracer(context.Background(), disabled); err != nil {
			t.Errorf("InitOtelTracer(disabled) failed: %v", err)
			break
		}
	}

	close(stop)
	wg.Wait()

	if torn != 0 {
		t.Fatalf("observed %d torn (tracer, active) snapshots; INV-OTEL-C1 violated", torn)
	}
	if nilTracer != 0 {
		t.Fatalf("observed %d nil tracer reads", nilTracer)
	}
}

func TestOtelConfigReloadDeduplication(t *testing.T) {
	cfg1 := &OtelConfig{
		Enabled:     true,
		Endpoint:    "127.0.0.1:4317",
		Protocol:    "grpc",
		Insecure:    true,
		ServiceName: "vproxy-dedup",
	}

	shutdown, err := InitOtelTracer(context.Background(), cfg1)
	if err != nil {
		t.Fatalf("first InitOtelTracer failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	p1 := globalTracerProvider
	if p1 == nil {
		t.Fatalf("expected globalTracerProvider to be non-nil")
	}

	// Reload with identical config (simulating config file reload when other fields changed)
	cfg2 := &OtelConfig{
		Enabled:     true,
		Endpoint:    "127.0.0.1:4317",
		Protocol:    "grpc",
		Insecure:    true,
		ServiceName: "vproxy-dedup",
	}
	shutdown2, err := InitOtelTracer(context.Background(), cfg2)
	if err != nil {
		t.Fatalf("second InitOtelTracer failed: %v", err)
	}

	p2 := globalTracerProvider
	if p1 != p2 {
		t.Fatalf("expected TracerProvider to be preserved on identical config reload, but got different instance")
	}

	// Now reload with modified config
	cfg3 := &OtelConfig{
		Enabled:     true,
		Endpoint:    "127.0.0.1:4318",
		Protocol:    "http",
		Insecure:    true,
		ServiceName: "vproxy-dedup",
	}
	shutdown3, err := InitOtelTracer(context.Background(), cfg3)
	if err != nil {
		t.Fatalf("third InitOtelTracer failed: %v", err)
	}
	_ = shutdown2
	_ = shutdown3

	p3 := globalTracerProvider
	if p3 == p1 {
		t.Fatalf("expected TracerProvider to be replaced on modified config, but it was unchanged")
	}
}

func TestOtelDefaultSampleRate(t *testing.T) {
	// Verify that omitting sample_rate (0.0) defaults to AlwaysSample (1.0)
	cfg := &OtelConfig{
		Enabled:     true,
		Endpoint:    "127.0.0.1:4317",
		Protocol:    "grpc",
		Insecure:    true,
		ServiceName: "vproxy-sampler",
		SampleRate:  0, // omitted in config
	}
	tp, _, err := buildOtelProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildOtelProvider failed: %v", err)
	}
	defer tp.Shutdown(context.Background())

	// Start a span and verify it is sampled
	tr := tp.Tracer("test")
	_, span := tr.Start(context.Background(), "test.sample")
	defer span.End()

	if !span.SpanContext().IsSampled() {
		t.Fatalf("expected span to be sampled when sample_rate is omitted (default 1.0), but got unsampled")
	}
}

func TestRelayWithStats(t *testing.T) {
	l, r := net.Pipe()
	defer l.Close()
	defer r.Close()

	go func() {
		_, _ = l.Write([]byte("hello client"))
		buf := make([]byte, 100)
		_, _ = l.Read(buf)
		_ = l.Close()
	}()

	go func() {
		buf := make([]byte, 100)
		_, _ = r.Read(buf)
		_, _ = r.Write([]byte("hello server response"))
		_ = r.Close()
	}()

	// Since Pipe is synchronous and Relay connects two ends, let's test RelayWithStats with standard net.Pipe
	c1, c2 := net.Pipe()
	s1, s2 := net.Pipe()

	go func() {
		_, _, _ = RelayWithStats(context.Background(), c1, s1)
	}()

	// Client sends to c2
	sendMsg := "ping from client"
	go func() {
		_, _ = c2.Write([]byte(sendMsg))
	}()

	// Server reads from s2
	buf := make([]byte, 64)
	n, err := s2.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != sendMsg {
		t.Fatalf("unexpected message: %s", string(buf[:n]))
	}

	// Server replies to s2
	respMsg := "pong from server"
	go func() {
		_, _ = s2.Write([]byte(respMsg))
		_ = s2.Close()
	}()

	// Client reads from c2
	n, err = c2.Read(buf)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	if string(buf[:n]) != respMsg {
		t.Fatalf("unexpected response message: %s", string(buf[:n]))
	}

	_ = c2.Close()
	time.Sleep(50 * time.Millisecond)
}
