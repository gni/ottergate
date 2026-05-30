package controlplane

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"ottergate/pkg/config"
)

func setupTestControlPlane(t *testing.T) (*ControlPlane, string) {
	tmpDir, err := os.MkdirTemp("", "ottergate-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %s", err)
	}

	configFilePath := filepath.Join(tmpDir, "config.json")
	initialCfg := &config.ServerConfig{
		Port:            53,
		FallbackDns:     "1.1.1.1",
		DnsCacheMaxSize: 1024,
		DnsCacheTtlMs:   60000,
		Hosts:           map[string]config.HostConfig{},
	}

	data, err := json.Marshal(initialCfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %s", err)
	}

	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		t.Fatalf("failed to write config file: %s", err)
	}

	cp := NewControlPlane(
		8080,
		"",
		"test-api-key-secret-123",
		"test-blind-index-salt-456",
		initialCfg,
		configFilePath,
		nil,
	)

	return cp, tmpDir
}

func TestGetControlPlaneStatusUnauthenticated(t *testing.T) {
	cp, tmpDir := setupTestControlPlane(t)
	defer os.RemoveAll(tmpDir)

	req := httptest.NewRequest("GET", "/api/v1/controlplane-status", nil)
	w := httptest.NewRecorder()

	cp.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Missing API Key") {
		t.Errorf("expected error 'Missing API Key', got '%s'", string(body))
	}
}

func TestGetControlPlaneStatusAuthenticated(t *testing.T) {
	cp, tmpDir := setupTestControlPlane(t)
	defer os.RemoveAll(tmpDir)

	req := httptest.NewRequest("GET", "/api/v1/controlplane-status", nil)
	req.Header.Set("X-Api-Key", "test-api-key-secret-123")
	req.Header.Set("X-Device-Id", "workstation-100")
	w := httptest.NewRecorder()

	cp.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var status map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %s", err)
	}

	if status["port"].(float64) != 8080 {
		t.Errorf("expected port 8080, got %v", status["port"])
	}

	if status["blindIndexSalt"].(string) != "test-blind-index-salt-456" {
		t.Errorf("expected salt, got %v", status["blindIndexSalt"])
	}

	if status["subscribersCount"].(float64) != 0 {
		t.Errorf("expected 0 subscribers, got %v", status["subscribersCount"])
	}
}

func TestGetPowChallengeAndAtomicMutation(t *testing.T) {
	cp, tmpDir := setupTestControlPlane(t)
	defer os.RemoveAll(tmpDir)

	// 1. Construct modified configuration payload using exact HostConfig schema
	newCfg := &config.ServerConfig{
		Port:            53,
		FallbackDns:     "8.8.8.8",
		DnsCacheMaxSize: 2048,
		DnsCacheTtlMs:   120000,
		Hosts: map[string]config.HostConfig{
			"custom.domain": {
				Records: []config.DnsRecord{
					{Type: "A", Address: "10.0.0.1"},
				},
			},
		},
	}
	payloadBytes, err := json.Marshal(newCfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %s", err)
	}

	// 2. Compute Payload Hash
	hPay := sha256.New()
	hPay.Write(payloadBytes)
	payloadHash := hex.EncodeToString(hPay.Sum(nil))

	// 3. Get PoW Challenge
	challengeReq := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/pow-challenge?payload_hash=%s", payloadHash), nil)
	challengeReq.Header.Set("X-Api-Key", "test-api-key-secret-123")
	challengeReq.Header.Set("X-Device-Id", "workstation-100")
	wChallenge := httptest.NewRecorder()

	cp.ServeHTTP(wChallenge, challengeReq)

	if wChallenge.Result().StatusCode != http.StatusOK {
		t.Fatalf("failed to get challenge: status %d", wChallenge.Result().StatusCode)
	}

	var challengeData map[string]string
	if err := json.NewDecoder(wChallenge.Result().Body).Decode(&challengeData); err != nil {
		t.Fatalf("failed to decode challenge: %s", err)
	}
	challenge := challengeData["challenge"]

	// 4. Solve Proof of Work constraint (Starts with "0000")
	var nonce int
	var nonceStr string
	for {
		nonceStr = fmt.Sprintf("%d", nonce)
		h := sha256.New()
		h.Write([]byte(challenge + nonceStr))
		hashStr := hex.EncodeToString(h.Sum(nil))
		if strings.HasPrefix(hashStr, "0000") {
			break
		}
		nonce++
	}

	// 5. Submit config PUT mutation with solved nonce
	mutationReq := httptest.NewRequest("PUT", "/api/v1/config", bytes.NewReader(payloadBytes))
	mutationReq.Header.Set("X-Api-Key", "test-api-key-secret-123")
	mutationReq.Header.Set("X-Device-Id", "workstation-100")
	mutationReq.Header.Set("X-Pow-Nonce", nonceStr)
	wMutation := httptest.NewRecorder()

	cp.ServeHTTP(wMutation, mutationReq)

	resp := wMutation.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mutation failed: status %d", resp.StatusCode)
	}

	var mutationResult map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&mutationResult); err != nil {
		t.Fatalf("failed to decode mutation result: %s", err)
	}

	if mutationResult["success"].(bool) != true {
		t.Errorf("expected success true, got %v", mutationResult["success"])
	}

	// 6. Verify configuration file was atomically updated
	cp.mu.RLock()
	currentFallback := cp.cfg.FallbackDns
	currentCacheSize := cp.cfg.DnsCacheMaxSize
	cp.mu.RUnlock()

	if currentFallback != "8.8.8.8" {
		t.Errorf("expected FallbackDNS '8.8.8.8', got '%s'", currentFallback)
	}
	if currentCacheSize != 2048 {
		t.Errorf("expected cache size 2048, got %d", currentCacheSize)
	}
}

func TestPutConfigWithInvalidProofOfWork(t *testing.T) {
	cp, tmpDir := setupTestControlPlane(t)
	defer os.RemoveAll(tmpDir)

	newCfg := &config.ServerConfig{
		Port:            53,
		FallbackDns:     "8.8.8.8",
		DnsCacheMaxSize: 2048,
		Hosts:           map[string]config.HostConfig{},
	}
	payloadBytes, _ := json.Marshal(newCfg)

	mutationReq := httptest.NewRequest("PUT", "/api/v1/config", bytes.NewReader(payloadBytes))
	mutationReq.Header.Set("X-Api-Key", "test-api-key-secret-123")
	mutationReq.Header.Set("X-Device-Id", "workstation-100")
	mutationReq.Header.Set("X-Pow-Nonce", "invalid-nonce-9999")
	wMutation := httptest.NewRecorder()

	cp.ServeHTTP(wMutation, mutationReq)

	resp := wMutation.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status %d (Forbidden), got %d", http.StatusForbidden, resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid Proof of Work Challenge") {
		t.Errorf("expected error 'Invalid Proof of Work Challenge', got '%s'", string(body))
	}
}

func TestGracefulTlsConfigFailure(t *testing.T) {
	tc := &config.TlsConfig{
		Cert: "/nonexistent/path/server.crt",
		Key:  "/nonexistent/path/server.key",
	}

	// 1. Verify loadTlsConfig succeeds on startup but the GetCertificate callback fails gracefully for missing files
	tlsCfg, err := loadTlsConfig(tc)
	if err != nil {
		t.Fatalf("expected loadTlsConfig to succeed on startup, got error: %v", err)
	}
	_, cbErr := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if cbErr == nil {
		t.Fatal("expected GetCertificate callback to fail when files are missing, got nil")
	}
	if !strings.Contains(cbErr.Error(), "failed to read cert") {
		t.Errorf("expected cert read error from callback, got: %v", cbErr)
	}

	// 2. Verify ControlPlane starts up successfully and binds a TLS listener
	tmpDir, err := os.MkdirTemp("", "ottergate-test-tls-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	configFilePath := filepath.Join(tmpDir, "config.json")
	initialCfg := &config.ServerConfig{
		Port:            53,
		FallbackDns:     "1.1.1.1",
		Hosts:           map[string]config.HostConfig{},
	}
	data, _ := json.Marshal(initialCfg)
	_ = os.WriteFile(configFilePath, data, 0644)

	// Construct ControlPlane with configured but missing certificates
	cp := NewControlPlane(
		0, // random available port
		"",
		"test-api-key",
		"test-salt",
		initialCfg,
		configFilePath,
		tc,
	)

	// Since port is 0, net.Listen("tcp", "0.0.0.0:0") will bind to a random free port.
	if err := cp.Start(); err != nil {
		t.Fatalf("ControlPlane.Start() returned error: %v (expected it to start successfully and handle handshakes dynamically)", err)
	}
	defer cp.Stop()

	// Verify it reports as TLS enabled
	cp.mu.RLock()
	tlsActive := cp.tlsActive
	cp.mu.RUnlock()

	if !tlsActive {
		t.Error("expected Control Plane to have tlsActive = true since TLS is configured and active")
	}
}
