package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	jsonlTraceFilePath = "/tmp/vproxy-traces.jsonl"
)

// TraceEntry represents a single structured HTTP/HTTPS transaction trace.
type TraceEntry struct {
	ID           string              `json:"id"`
	Timestamp    time.Time           `json:"timestamp"`
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Path         string              `json:"path"`
	Host         string              `json:"host"`
	RequestProto string              `json:"request_proto"`
	ReqHeaders   map[string][]string `json:"req_headers"`
	ReqBody      string              `json:"req_body,omitempty"`
	StatusCode   int                 `json:"status_code"`
	RespHeaders  map[string][]string `json:"resp_headers"`
	RespBody     string              `json:"resp_body,omitempty"`
	LatencyMs    float64             `json:"latency_ms"`
}

// TraceFormatter defines the interface to process/format a TraceEntry.
type TraceFormatter interface {
	Format(entry *TraceEntry)
}

var (
	activeFormatters []TraceFormatter
	formattersMu     sync.Mutex
)

// RegisterFormatter registers a new trace formatter destination.
func RegisterFormatter(tf TraceFormatter) {
	formattersMu.Lock()
	defer formattersMu.Unlock()
	activeFormatters = append(activeFormatters, tf)
}

// PublishTrace publishes a trace entry to all active formatters.
func PublishTrace(entry *TraceEntry) {
	formattersMu.Lock()
	formatters := make([]TraceFormatter, len(activeFormatters))
	copy(formatters, activeFormatters)
	formattersMu.Unlock()

	for _, f := range formatters {
		f.Format(entry)
	}
}

// TextConsoleFormatter prints human-readable trace logs to the console logger.
type TextConsoleFormatter struct{}

func (tcf *TextConsoleFormatter) Format(entry *TraceEntry) {
	Infof("[%s] >>> API Request: %s %s", entry.ID, entry.Method, entry.URL)
	if len(entry.ReqHeaders) > 0 {
		Debugf("[%s] Request Headers: %v", entry.ID, entry.ReqHeaders)
	}
	if len(entry.ReqBody) > 0 {
		Debugf("[%s] Request Body: %s", entry.ID, entry.ReqBody)
	}

	Infof("[%s] <<< API Response: %s (Status: %d, Latency: %.2fms)", entry.ID, entry.Path, entry.StatusCode, entry.LatencyMs)
	if len(entry.RespHeaders) > 0 {
		Debugf("[%s] Response Headers: %v", entry.ID, entry.RespHeaders)
	}
	if len(entry.RespBody) > 0 {
		bodyStr := entry.RespBody
		if len(bodyStr) > 1024 {
			bodyStr = bodyStr[:1024] + "... [truncated]"
		}
		Debugf("[%s] Response Body: %s", entry.ID, bodyStr)
	}
}

// JSONFileFormatter appends standard JSON Lines (JSONL) to /tmp/vproxy-traces.jsonl.
type JSONFileFormatter struct {
	mu sync.Mutex
}

func (jff *JSONFileFormatter) Format(entry *TraceEntry) {
	jff.mu.Lock()
	defer jff.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	f, err := os.OpenFile(jsonlTraceFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

// MemoryTraceFormatter keeps the last N traces in memory.
type MemoryTraceFormatter struct {
	mu     sync.Mutex
	Traces []*TraceEntry
	Max    int
}

func NewMemoryTraceFormatter(max int) *MemoryTraceFormatter {
	return &MemoryTraceFormatter{
		Traces: make([]*TraceEntry, 0, max),
		Max:    max,
	}
}

func (m *MemoryTraceFormatter) Format(entry *TraceEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Traces) >= m.Max {
		// Remove oldest
		m.Traces = m.Traces[1:]
	}
	m.Traces = append(m.Traces, entry)
}

func (m *MemoryTraceFormatter) GetTraces() []*TraceEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy
	res := make([]*TraceEntry, len(m.Traces))
	copy(res, m.Traces)
	return res
}

func init() {
	// Automatically register default formatters on startup
	RegisterFormatter(&TextConsoleFormatter{})
	RegisterFormatter(&JSONFileFormatter{})
}

// ProcessBody returns the text content of the body, or a binary descriptor like "[1.2KB:binary]" if it contains binary data.
func ProcessBody(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if IsBinary(data) {
		return FormatBinaryDesc(len(data))
	}
	return string(data)
}

// IsBinary checks if a byte slice contains binary control characters.
func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	limit := len(data)
	if limit > 512 {
		limit = 512
	}
	for i := 0; i < limit; i++ {
		b := data[i]
		if b == 0 {
			return true
		}
		if b < 32 && b != '\t' && b != '\r' && b != '\n' {
			return true
		}
	}
	return false
}

// FormatBinaryDesc formats a byte length into a human-readable string like "[1.2KB:binary]".
func FormatBinaryDesc(bytesLen int) string {
	if bytesLen < 1024 {
		if bytesLen == 1 {
			return "[1byte:binary]"
		}
		return fmt.Sprintf("[%dbytes:binary]", bytesLen)
	}
	kb := float64(bytesLen) / 1024.0
	if kb < 1024 {
		return fmt.Sprintf("[%.1fKB:binary]", kb)
	}
	mb := kb / 1024.0
	return fmt.Sprintf("[%.1fMB:binary]", mb)
}
