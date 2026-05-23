package internal

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/metadata"
)

type traceKey struct{}
type startTimeKey struct{}

// GetTraceID returns the trace ID from the context, or empty string if not present.
// It also checks gRPC metadata for "x-trace-id".
func GetTraceID(ctx context.Context) string {
	if id, ok := ctx.Value(traceKey{}).(string); ok {
		return id
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ids := md.Get("x-trace-id"); len(ids) > 0 {
			return ids[0]
		}
	}
	return ""
}

// TraceInfof logs info with trace ID and elapsed time if available.
func TraceInfof(ctx context.Context, format string, v ...interface{}) {
	id := GetTraceID(ctx)
	deadline, ok := ctx.Deadline()
	var extra string
	if ok {
		extra += fmt.Sprintf(" [D: %v]", time.Until(deadline).Round(time.Millisecond))
	}
	if start, ok := ctx.Value(startTimeKey{}).(time.Time); ok {
		extra += fmt.Sprintf(" [T+ %v]", time.Since(start).Round(time.Millisecond))
	}

	if id != "" {
		Infof("[%s]%s "+format, append([]interface{}{id, extra}, v...)...)
	} else {
		Infof(extra+" "+format, v...)
	}
}

// TraceErrorf logs error with trace ID and elapsed time if available.
func TraceErrorf(ctx context.Context, format string, v ...interface{}) {
	id := GetTraceID(ctx)
	deadline, ok := ctx.Deadline()
	var extra string
	if ok {
		extra += fmt.Sprintf(" [D: %v]", time.Until(deadline).Round(time.Millisecond))
	}
	if start, ok := ctx.Value(startTimeKey{}).(time.Time); ok {
		extra += fmt.Sprintf(" [T+ %v]", time.Since(start).Round(time.Millisecond))
	}

	if id != "" {
		Errorf("[%s]%s "+format, append([]interface{}{id, extra}, v...)...)
	} else {
		Errorf(extra+" "+format, v...)
	}
}

// TraceDebugf logs debug with trace ID if available.
func TraceDebugf(ctx context.Context, format string, v ...interface{}) {
	id := GetTraceID(ctx)
	if id != "" {
		Debugf("[%s] "+format, append([]interface{}{id}, v...)...)
	} else {
		Debugf(format, v...)
	}
}
