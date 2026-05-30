package proxy

import (
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
