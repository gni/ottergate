package proxy

import (
	"encoding/binary"
	"testing"
	"time"
	"ottergate/pkg/config"
)

func TestNewSniProxyServiceAndUpdates(t *testing.T) {
	cfg := &config.ServerConfig{
		Port:             53,
		FallbackDns:      "1.1.1.1",
		TcpIdleTimeoutMs: 10000,
	}

	service := NewSniProxyService(cfg)

	if service.port != 443 { // default HttpsPort if nil
		t.Errorf("expected default HttpsPort 443, got %d", service.port)
	}
	if service.idleTimeout != 10*time.Second {
		t.Errorf("expected idleTimeout 10s, got %v", service.idleTimeout)
	}

	newPort := 8443
	newCfg := &config.ServerConfig{
		HttpsPort:        &newPort,
		TcpIdleTimeoutMs: 20000,
	}

	service.UpdateConfig(newCfg)

	if service.port != 8443 {
		t.Errorf("expected updated port 8443, got %d", service.port)
	}
	if service.idleTimeout != 20*time.Second {
		t.Errorf("expected idleTimeout 20s, got %v", service.idleTimeout)
	}
}

func TestExtractSNINotTLS(t *testing.T) {
	// 1. Invalid prefix header (not 0x16 Handshake)
	_, err := extractSNI([]byte{0x00, 0x01, 0x02, 0x03, 0x04})
	if err == nil {
		t.Error("expected error for non-TLS signature, got nil")
	}

	// 2. Truncated handshake
	_, errTrunc := extractSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	if errTrunc == nil {
		t.Error("expected error for truncated ClientHello header, got nil")
	}
}

func TestExtractSNIValid(t *testing.T) {
	// Build a mock valid client hello containing SNI: "test.local"
	// Length values and structure according to TLS ClientHello specs
	host := "test.local"
	hostBytes := []byte(host)

	// Build SNI extension:
	// - Extension Type: 0x0000 (2 bytes)
	// - Extension Length: len(hostBytes) + 5 (2 bytes)
	// - SNI Server Name List Length: len(hostBytes) + 3 (2 bytes)
	// - Server Name Type: 0x00 Hostname (1 byte)
	// - Server Name Length: len(hostBytes) (2 bytes)
	// - Server Name: Hostname bytes
	sniExt := make([]byte, 4+2+1+2+len(hostBytes))
	binary.BigEndian.PutUint16(sniExt[0:2], 0x0000) // Extension Type: SNI
	binary.BigEndian.PutUint16(sniExt[2:4], uint16(len(hostBytes)+5)) // Extension Length
	binary.BigEndian.PutUint16(sniExt[4:6], uint16(len(hostBytes)+3)) // List Length
	sniExt[6] = 0x00 // Name Type: Hostname
	binary.BigEndian.PutUint16(sniExt[7:9], uint16(len(hostBytes))) // Hostname Length
	copy(sniExt[9:], hostBytes)

	// Build extensions container block:
	// - Extensions length (2 bytes)
	// - SNI extension
	extBlock := make([]byte, 2+len(sniExt))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(sniExt)))
	copy(extBlock[2:], sniExt)

	// Build ClientHello body (excluding session/cipher suites for simplicity of offset math):
	// Offset logic in sni.go:
	// - Session ID length: data[43]
	// - Cipher suites length: BigEndian.Uint16(data[43 + 1 + session_id_len])
	// - Compression methods: data[offset]
	// - Extensions: offset + 1 + compression_len
	data := make([]byte, 43+1+32+2+4+1+1+len(extBlock)) // total block size
	data[0] = 0x16 // Handshake Record Type
	data[1] = 0x03 // TLS version 1.2
	data[2] = 0x01
	// Handshake Type: ClientHello (1) at byte 5
	data[5] = 0x01

	// Session ID length = 32 bytes (at byte 43)
	data[43] = 32

	// Cipher Suites offset = 43 + 1 + 32 = 76
	// Let's set cipher suites length = 4 bytes (at byte 76)
	binary.BigEndian.PutUint16(data[76:78], 4)

	// Compression methods offset = 76 + 2 + 4 = 82
	// Let's set compression methods length = 1 byte (at byte 82)
	data[82] = 1

	// Extensions offset = 82 + 1 + 1 = 84
	copy(data[84:], extBlock)

	sni, err := extractSNI(data)
	if err != nil {
		t.Fatalf("unexpected error extracting SNI: %v", err)
	}

	if sni != host {
		t.Errorf("expected extracted SNI to be '%s', got '%s'", host, sni)
	}
}
