package internal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestWebServerStaticDistFallback(t *testing.T) {
	// 1. Test fallback when dist dir is empty/missing
	SetFrontendDistDir("/non/existent/dist/dir")
	defer SetFrontendDistDir("")

	reqRoot := httptest.NewRequest("GET", "/", nil)
	rrRoot := httptest.NewRecorder()
	handleIndex(rrRoot, reqRoot)

	if rrRoot.Code != http.StatusOK {
		t.Fatalf("Expected fallback 200 OK for root, got %d", rrRoot.Code)
	}
	if !strings.Contains(rrRoot.Body.String(), "vproxy Dashboard") {
		t.Fatalf("Expected fallback indexHTML, got: %s", rrRoot.Body.String())
	}

	reqMissing := httptest.NewRequest("GET", "/nonexistent-route", nil)
	rrMissing := httptest.NewRecorder()
	handleIndex(rrMissing, reqMissing)
	if rrMissing.Code != http.StatusNotFound {
		t.Fatalf("Expected 404 for missing route when dist missing, got %d", rrMissing.Code)
	}

	// 2. Test when distDir exists with mock index.html and static asset
	tmpDir, err := os.MkdirTemp("", "vproxy_dist_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mockIndex := "<html><body><h1>FluentUI Dashboard</h1></body></html>"
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(mockIndex), 0644); err != nil {
		t.Fatalf("Failed to write mock index.html: %v", err)
	}

	assetsDir := filepath.Join(tmpDir, "assets")
	os.MkdirAll(assetsDir, 0755)
	mockJS := "console.log('fluentui');"
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), []byte(mockJS), 0644); err != nil {
		t.Fatalf("Failed to write mock app.js: %v", err)
	}

	SetFrontendDistDir(tmpDir)

	// Root route
	reqSPA := httptest.NewRequest("GET", "/", nil)
	rrSPA := httptest.NewRecorder()
	handleIndex(rrSPA, reqSPA)

	if rrSPA.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for SPA root, got %d", rrSPA.Code)
	}
	if !strings.Contains(rrSPA.Body.String(), "FluentUI Dashboard") {
		t.Fatalf("Expected mockIndex content, got %s", rrSPA.Body.String())
	}

	// SPA route (e.g. /traces or /config) should return index.html
	reqRoute := httptest.NewRequest("GET", "/traces", nil)
	rrRoute := httptest.NewRecorder()
	handleIndex(rrRoute, reqRoute)

	if rrRoute.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for SPA route /traces, got %d", rrRoute.Code)
	}
	if !strings.Contains(rrRoute.Body.String(), "FluentUI Dashboard") {
		t.Fatalf("Expected index.html for SPA route /traces, got %s", rrRoute.Body.String())
	}

	// Static asset route (/assets/app.js)
	reqAsset := httptest.NewRequest("GET", "/assets/app.js", nil)
	rrAsset := httptest.NewRecorder()
	handleIndex(rrAsset, reqAsset)

	if rrAsset.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for static asset, got %d", rrAsset.Code)
	}
	if !strings.Contains(rrAsset.Body.String(), "console.log('fluentui')") {
		t.Fatalf("Expected asset content, got %s", rrAsset.Body.String())
	}
}

func TestWebServerEmbeddedDist(t *testing.T) {
	SetFrontendDistDir("")
	orig := embeddedDist
	defer func() { embeddedDist = orig }()

	embeddedDist = fstest.MapFS{
		"index.html":    {Data: []byte("<html>EmbeddedDashboard</html>")},
		"assets/app.js": {Data: []byte("console.log('embedded')")},
	}

	cases := []struct{ path, want string }{
		{"/", "EmbeddedDashboard"},
		{"/config", "EmbeddedDashboard"}, // SPA fallback
		{"/assets/app.js", "console.log('embedded')"},
	}
	for _, c := range cases {
		rr := httptest.NewRecorder()
		handleIndex(rr, httptest.NewRequest("GET", c.path, nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), c.want) {
			t.Fatalf("%s: code=%d body=%q, want %q", c.path, rr.Code, rr.Body.String(), c.want)
		}
	}

	// Path traversal must not escape the embedded FS.
	rr := httptest.NewRecorder()
	handleIndex(rr, httptest.NewRequest("GET", "/../../etc/passwd", nil))
	if strings.Contains(rr.Body.String(), "root:") {
		t.Fatal("path traversal leaked file content")
	}

	// Embedded FS without index.html (placeholder only) falls back to built-in HTML.
	embeddedDist = fstest.MapFS{".gitkeep": {Data: nil}}
	rr = httptest.NewRecorder()
	handleIndex(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "vproxy Dashboard") {
		t.Fatalf("expected built-in fallback HTML, got %q", rr.Body.String())
	}
}
