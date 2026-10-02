package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"ottergate/pkg/config"
)

func TestNewHttpHandlerAndUpdates(t *testing.T) {
	cfg := &config.ServerConfig{
		Port:             53,
		FallbackDns:      "1.1.1.1",
		TcpIdleTimeoutMs: 15000,
	}

	handler := NewHttpHandler(cfg)

	if handler.port != 80 { // default HttpPort if nil
		t.Errorf("expected default HttpPort 80, got %d", handler.port)
	}
	if handler.idleTimeout != 15*time.Second {
		t.Errorf("expected idleTimeout 15s, got %v", handler.idleTimeout)
	}

	// Update configuration
	newPort := 8082
	newCfg := &config.ServerConfig{
		HttpPort:         &newPort,
		TcpIdleTimeoutMs: 30000,
	}

	handler.UpdateConfig(newCfg)

	if handler.port != 8082 {
		t.Errorf("expected updated port 8082, got %d", handler.port)
	}
	if handler.idleTimeout != 30*time.Second {
		t.Errorf("expected idleTimeout 30s, got %v", handler.idleTimeout)
	}
}

func TestSanitizeHeader(t *testing.T) {
	// 1. Valid header
	val, err := sanitizeHeader("valid-header-value")
	if err != nil || val != "valid-header-value" {
		t.Errorf("expected valid header to pass, got: %v", err)
	}

	// 2. CRLF injection check
	_, errLf := sanitizeHeader("header\nvalue")
	if errLf == nil {
		t.Error("expected error for header containing LF")
	}

	_, errCr := sanitizeHeader("header\rvalue")
	if errCr == nil {
		t.Error("expected error for header containing CR")
	}

	_, errTab := sanitizeHeader("header\tvalue")
	if errTab == nil {
		t.Error("expected error for header containing tab")
	}

	// 3. Control character check
	_, errCtrl := sanitizeHeader("header" + string(rune(0x07)) + "value")
	if errCtrl == nil {
		t.Error("expected error for header containing control character BEL")
	}

	// 4. Overlong header check
	overlong := strings.Repeat("a", 8193)
	_, errLong := sanitizeHeader(overlong)
	if errLong == nil {
		t.Error("expected error for overlong header value")
	}
}

func TestHttpProxyPostWithBodyAndQueryParams(t *testing.T) {
	var receivedBody []byte
	var receivedContentLength int64
	var receivedTransferEncoding []string
	var receivedURL string
	var receivedHost string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedContentLength = r.ContentLength
		receivedTransferEncoding = r.TransferEncoding
		receivedURL = r.URL.String()
		receivedHost = r.Host

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	cfg := &config.ServerConfig{
		Firewall: &config.FirewallConfig{
			DefaultPolicy: "allow",
			AllowlistIps:  []string{"127.0.0.1"},
		},
		Hosts: map[string]config.HostConfig{
			"agent.operations": {
				Records: []config.DnsRecord{
					{Type: "A", Address: "127.0.0.1"},
				},
				HttpProxy: &config.HttpProxyConfig{
					Enabled:             true,
					Upstream:            backend.URL,
					ForwardRequestBody:  true,
					MaxRequestBodyBytes: 1048576,
				},
			},
		},
	}

	handler := NewHttpHandler(cfg)

	// 1. Test POST with body and query params
	bodyPayload := `{"model":"test","messages":[{"role":"user","content":"hello"}]}`
	req, _ := http.NewRequest("POST", "http://agent.operations/v1/chat/completions?stream=true", bytes.NewBufferString(bodyPayload))
	req.RequestURI = "/v1/chat/completions?stream=true"
	req.Host = "agent.operations"
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyPayload)))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}

	if string(receivedBody) != bodyPayload {
		t.Errorf("expected body %q, got %q", bodyPayload, string(receivedBody))
	}

	if receivedContentLength != int64(len(bodyPayload)) {
		t.Errorf("expected Content-Length %d, got %d", len(bodyPayload), receivedContentLength)
	}

	if len(receivedTransferEncoding) > 0 {
		t.Errorf("expected no chunked transfer encoding, got %v", receivedTransferEncoding)
	}

	if receivedURL != "/v1/chat/completions?stream=true" {
		t.Errorf("expected URL '/v1/chat/completions?stream=true', got %q", receivedURL)
	}

	// 2. Test payload exceeding maxRequestBodyBytes returns 413
	cfg.Hosts["agent.operations"].HttpProxy.MaxRequestBodyBytes = 10
	largeBody := "this is a very long body exceeding 10 bytes"
	reqLarge, _ := http.NewRequest("POST", "http://agent.operations/v1/test", bytes.NewBufferString(largeBody))
	reqLarge.RequestURI = "/v1/test"
	reqLarge.Host = "agent.operations"
	reqLarge.RemoteAddr = "127.0.0.1:54321"
	reqLarge.Header.Set("Content-Length", fmt.Sprintf("%d", len(largeBody)))

	recLarge := httptest.NewRecorder()
	handler.ServeHTTP(recLarge, reqLarge)

	if recLarge.Result().StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Payload Too Large, got %d", recLarge.Result().StatusCode)
	}

	_ = receivedHost
}
