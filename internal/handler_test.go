package internal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/qtopie/vproxy/internal/mitm"
)

func TestMITMHTTPS(t *testing.T) {
	// Enable verbose mode to trigger MITM deep tracing
	SetVerbose(true)
	defer SetVerbose(false)

	// Ensure CA exists
	if err := mitm.EnsureCA(); err != nil {
		t.Fatalf("Failed to ensure CA: %v", err)
	}

	// 1. Create a target HTTPS test server
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Response", "from-target")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, MITM!"))
	}))
	defer targetServer.Close()

	targetURL, err := url.Parse(targetServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse target URL: %v", err)
	}

	// 2. Setup ServerManager and ProxyHandler
	// Using a wildcard rule to route the target through direct dial
	sm := NewServerManager([]string{}, 1*time.Minute, 1*time.Second)
	rm := NewRuleManager([]string{fmt.Sprintf("%s,DIRECT", targetURL.Hostname())})
	ph := NewProxyHandler(sm, rm, 0, 0, 0, 0) // Use 0 for dynamic ports

	if err := ph.StartHTTP(); err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	defer ph.Stop()

	// 3. Setup HttpClient with custom transport that uses our proxy and trusts our Root CA
	caCertPool := x509.NewCertPool()
	caCertBytes, err := os.ReadFile(mitm.GetCACertPath())
	if err != nil {
		t.Fatalf("Failed to read Root CA: %v", err)
	}
	if ok := caCertPool.AppendCertsFromPEM(caCertBytes); !ok {
		t.Fatal("Failed to append CA cert to pool")
	}

	// Also trust the target server's own test certificate
	targetCertBytes := targetServer.Certificate()
	if targetCertBytes != nil {
		caCertPool.AddCert(targetCertBytes)
	}

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", ph.HttpPort))
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true, // Bypass strict hostname check for httptest server localhost IPs
			},
		},
		Timeout: 5 * time.Second,
	}

	// 4. Send request through the proxy
	resp, err := client.Get(targetServer.URL)
	if err != nil {
		t.Fatalf("Failed to send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// 5. Verify the response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(body) != "Hello, MITM!" {
		t.Errorf("Expected body 'Hello, MITM!', got '%s'", string(body))
	}

	if val := resp.Header.Get("X-Test-Response"); val != "from-target" {
		t.Errorf("Expected header X-Test-Response 'from-target', got '%s'", val)
	}
}

type mockFormatter struct {
	mu     sync.Mutex
	traces []*TraceEntry
}

func (mf *mockFormatter) Format(entry *TraceEntry) {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	mf.traces = append(mf.traces, entry)
}

func TestTraceDecoupling(t *testing.T) {
	mf := &mockFormatter{}
	RegisterFormatter(mf)

	entry := &TraceEntry{
		ID:         "test-trace-123",
		Method:     "POST",
		URL:        "https://example.com/api/test",
		Path:       "/api/test",
		Host:       "example.com",
		StatusCode: 201,
		LatencyMs:  42.5,
	}

	PublishTrace(entry)

	mf.mu.Lock()
	defer mf.mu.Unlock()

	if len(mf.traces) != 1 {
		t.Fatalf("Expected 1 trace received in custom formatter, got %d", len(mf.traces))
	}

	received := mf.traces[0]
	if received.ID != "test-trace-123" {
		t.Errorf("Expected ID 'test-trace-123', got '%s'", received.ID)
	}
	if received.Method != "POST" {
		t.Errorf("Expected Method 'POST', got '%s'", received.Method)
	}
	if received.StatusCode != 201 {
		t.Errorf("Expected StatusCode 201, got %d", received.StatusCode)
	}
	if received.LatencyMs != 42.5 {
		t.Errorf("Expected LatencyMs 42.5, got %f", received.LatencyMs)
	}
}

func TestProcessBody(t *testing.T) {
	// 1. Plain text body
	textData := []byte("Hello, this is standard UTF-8 text!")
	if got := ProcessBody(textData); got != string(textData) {
		t.Errorf("Expected raw text string, got '%s'", got)
	}

	// 2. Binary body with NUL byte
	binData := []byte{0x00, 0x01, 0x02, 0x03}
	if got := ProcessBody(binData); got != "[4bytes:binary]" {
		t.Errorf("Expected '[4bytes:binary]', got '%s'", got)
	}

	// 3. Binary body with control chars
	largeBinData := make([]byte, 1500)
	largeBinData[0] = 0x0e // control char (non-printable)
	if got := ProcessBody(largeBinData); got != "[1.5KB:binary]" {
		t.Errorf("Expected '[1.5KB:binary]', got '%s'", got)
	}
}
