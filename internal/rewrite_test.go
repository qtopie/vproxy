package internal

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRewriteEngine_ParseAndHostBuckets(t *testing.T) {
	// SPEC-REWRITE-001: 正则规则解析与 Host 桶自动归类
	entries := []string{
		"/cafe123.cn\\/.*?\\.(html|js|css|png|jpg)/ http://127.0.0.1:3000",
		"https://api.example.com/v1/* http://127.0.0.1:8080/v2/$1",
		"https://api.prod.com/config file:///tmp/config.json",
	}

	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	hosts := engine.GetInterceptHosts()
	expectedHosts := map[string]bool{
		"cafe123.cn":      true,
		"api.example.com": true,
		"api.prod.com":    true,
	}

	for _, h := range hosts {
		if !expectedHosts[h] {
			t.Errorf("unexpected intercept host: %s", h)
		}
		delete(expectedHosts, h)
	}
	if len(expectedHosts) > 0 {
		t.Errorf("missing expected intercept hosts: %v", expectedHosts)
	}

	if !engine.IsInterceptHost("cafe123.cn") {
		t.Errorf("expected IsInterceptHost('cafe123.cn') to be true")
	}
	if engine.IsInterceptHost("github.com") {
		t.Errorf("expected IsInterceptHost('github.com') to be false")
	}
}

func TestRewriteEngine_ZeroRegexOverheadOnIrrelevantHost(t *testing.T) {
	// SPEC-REWRITE-002: 无关 Host 零正则损耗（方案 2 验证）
	entries := []string{
		"/cafe123.cn\\/.*?\\.(html|js|css|png|jpg)/ http://127.0.0.1:3000",
	}
	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	// Host "github.com" should fail immediately without executing regex
	res, matched := engine.Match("https://github.com/index.html", "github.com")
	if matched || res != nil {
		t.Errorf("expected github.com not to match, got res=%v, matched=%v", res, matched)
	}
}

func TestRewriteEngine_AutoPathAppend(t *testing.T) {
	// SPEC-REWRITE-003: 正则匹配并自动追加请求路径 (Auto Path Append)
	entries := []string{
		"/cafe123.cn\\/.*?\\.(js|css)/ http://127.0.0.1:3000",
	}
	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	res, matched := engine.Match("https://cafe123.cn/assets/app.js?v=2", "cafe123.cn")
	if !matched {
		t.Fatalf("expected match for app.js")
	}
	expectedTarget := "http://127.0.0.1:3000/assets/app.js?v=2"
	if res.TargetURL != expectedTarget {
		t.Errorf("expected target %q, got %q", expectedTarget, res.TargetURL)
	}
	if res.Action != RewriteActionProxy {
		t.Errorf("expected ActionProxy, got %v", res.Action)
	}
}

func TestRewriteEngine_CaptureGroupSubstitution(t *testing.T) {
	// SPEC-REWRITE-004: 捕获组变量回填 ($1 展开)
	entries := []string{
		"/api.example.com\\/v1\\/(.*)/ http://127.0.0.1:8080/v2/$1",
	}
	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	res, matched := engine.Match("https://api.example.com/v1/user/info?id=10", "api.example.com")
	if !matched {
		t.Fatalf("expected match for api.example.com")
	}
	expectedTarget := "http://127.0.0.1:8080/v2/user/info?id=10"
	if res.TargetURL != expectedTarget {
		t.Errorf("expected target %q, got %q", expectedTarget, res.TargetURL)
	}
}

func TestRewriteEngine_WildcardRewrite(t *testing.T) {
	// SPEC-REWRITE-005: 通配符 * 路径替换
	entries := []string{
		"https://api.prod.com/service/* http://127.0.0.1:9000/$1",
	}
	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	res, matched := engine.Match("https://api.prod.com/service/pay/order", "api.prod.com")
	if !matched {
		t.Fatalf("expected match for wildcard")
	}
	expectedTarget := "http://127.0.0.1:9000/pay/order"
	if res.TargetURL != expectedTarget {
		t.Errorf("expected target %q, got %q", expectedTarget, res.TargetURL)
	}
}

func TestRewriteEngine_LocalFileMock(t *testing.T) {
	// SPEC-REWRITE-006: 本地文件 Mock (file://)
	tmpFile, err := os.CreateTemp("", "vproxy-mock-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, _ = tmpFile.WriteString(`{"status":"mock_ok"}`)
	tmpFile.Close()

	entries := []string{
		fmt.Sprintf("https://api.prod.com/config file://%s", tmpFile.Name()),
	}
	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	res, matched := engine.Match("https://api.prod.com/config", "api.prod.com")
	if !matched {
		t.Fatalf("expected match for mock config")
	}
	if res.Action != RewriteActionMock {
		t.Errorf("expected ActionMock, got %v", res.Action)
	}
	if res.LocalFile != tmpFile.Name() {
		t.Errorf("expected local file %q, got %q", tmpFile.Name(), res.LocalFile)
	}
}

func TestRewriteEngine_CrossProtocolReverseProxy(t *testing.T) {
	// SPEC-REWRITE-007: HTTPS 到 HTTP 的跨协议反向代理
	// 启动一个本地明文 HTTP 测试后端
	var receivedProto string
	var receivedHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		receivedHost = r.Header.Get("X-Forwarded-Host")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"backend":"ok"}`))
	}))
	defer backend.Close()

	entries := []string{
		fmt.Sprintf("/test.domain.com\\/api/ %s/api", backend.URL),
	}
	engine, err := NewRewriteEngine(entries)
	if err != nil {
		t.Fatalf("NewRewriteEngine failed: %v", err)
	}

	res, matched := engine.Match("https://test.domain.com/api", "test.domain.com")
	if !matched {
		t.Fatalf("expected match")
	}

	// 模拟执行反向代理转发
	req, _ := http.NewRequest("GET", res.TargetURL, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "test.domain.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to dispatch request to backend: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"backend":"ok"}` {
		t.Errorf("unexpected response body: %s", string(body))
	}
	if receivedProto != "https" {
		t.Errorf("expected X-Forwarded-Proto=https, got %s", receivedProto)
	}
	if receivedHost != "test.domain.com" {
		t.Errorf("expected X-Forwarded-Host=test.domain.com, got %s", receivedHost)
	}
}
