package dns

import (
	"encoding/binary"
	"testing"
	"ottergate/pkg/config"
)

func TestNewDnsHandlerAndUpdates(t *testing.T) {
	cfg := &config.ServerConfig{
		Port:                 53,
		FallbackDns:          "1.1.1.1",
		RateLimitMaxRequests: 100,
		RateLimitWindowMs:    1000,
		MaxTcpConnections:    150,
	}

	server := NewDevDnsServer(cfg)
	handler := NewDnsHandler(server, cfg)

	if handler.port != 53 {
		t.Errorf("expected port 53, got %d", handler.port)
	}
	if handler.fallbackDns != "1.1.1.1" {
		t.Errorf("expected fallback 1.1.1.1, got %s", handler.fallbackDns)
	}
	if handler.maxTcpConns != 150 {
		t.Errorf("expected max TCP conns 150, got %d", handler.maxTcpConns)
	}
	if handler.rateLimiter == nil {
		t.Error("expected rateLimiter to be initialized")
	}

	// Test UpdateConfig
	newCfg := &config.ServerConfig{
		Port:                 54,
		FallbackDns:          "8.8.8.8",
		MaxTcpConnections:    200,
		RateLimitMaxRequests: 0, // disables rate limiter
	}

	handler.UpdateConfig(newCfg)

	if handler.port != 54 {
		t.Errorf("expected port 54, got %d", handler.port)
	}
	if handler.fallbackDns != "8.8.8.8" {
		t.Errorf("expected fallback 8.8.8.8, got %s", handler.fallbackDns)
	}
	if handler.maxTcpConns != 200 {
		t.Errorf("expected max TCP conns 200, got %d", handler.maxTcpConns)
	}
}

func TestAppendEdns0DoBit(t *testing.T) {
	// Construct minimal valid DNS header (QDCOUNT = 1)
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[4:6], 1)

	// Append question: "test.local" type A (1) class IN (1)
	dw := NewDnsWireFormat(query)
	dw.Offset = 12
	dw.WriteDomainName("test.local")
	dw.WriteUint16(1)
	dw.WriteUint16(1)
	query = dw.Finish()

	res := AppendEdns0DoBit(query)

	if len(res) <= len(query) {
		t.Fatal("expected result to be longer after appending EDNS0 record")
	}

	// Verify ARCOUNT in header is updated to 1
	arcount := binary.BigEndian.Uint16(res[10:12])
	if arcount != 1 {
		t.Errorf("expected ARCOUNT to be updated to 1, got %d", arcount)
	}
}
