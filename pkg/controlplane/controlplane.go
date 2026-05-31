package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"ottergate/pkg/audit"
	"ottergate/pkg/config"
	"ottergate/pkg/crypto"
)

type ControlPlane struct {
	mu                 sync.RWMutex
	cfg                *config.ServerConfig
	port               int
	socketPath         string
	apiKey             string
	blindIndexSalt     string
	configFilePath     string
	tlsCfg             *config.TlsConfig
	listener           net.Listener
	subscribers        []func(*config.ServerConfig)
	seenNonces         map[string]bool
	currentPoWWindow   int64
	expectedApiKeyHash string
	apiKeySecret       []byte
	deviceSecret       []byte
	tlsActive          bool
	stopChan           chan struct{}
}

func NewControlPlane(
	port int,
	socketPath string,
	apiKey string,
	blindIndexSalt string,
	initialConfig *config.ServerConfig,
	configFilePath string,
	tlsCfg *config.TlsConfig,
) *ControlPlane {
	apiKeySecret := crypto.HKDF([]byte(blindIndexSalt), nil, []byte("api_key_derivation"), 32)
	deviceSecret := crypto.HKDF([]byte(blindIndexSalt), nil, []byte("device_id_derivation"), 32)

	mac := hmac.New(sha256.New, apiKeySecret)
	mac.Write([]byte(apiKey))
	expectedHash := hex.EncodeToString(mac.Sum(nil))

	if port == 0 {
		port = 8080
	}

	return &ControlPlane{
		cfg:                initialConfig,
		port:               port,
		socketPath:         socketPath,
		apiKey:             apiKey,
		blindIndexSalt:     blindIndexSalt,
		configFilePath:     filepath.Clean(configFilePath),
		tlsCfg:             tlsCfg,
		seenNonces:         make(map[string]bool),
		expectedApiKeyHash: expectedHash,
		apiKeySecret:       apiKeySecret,
		deviceSecret:       deviceSecret,
		stopChan:           make(chan struct{}),
	}
}

func (cp *ControlPlane) Subscribe(callback func(*config.ServerConfig)) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.subscribers = append(cp.subscribers, callback)
}

func resolveTlsMaterial(data string) ([]byte, error) {
	if strings.Contains(data, "-----BEGIN") {
		return []byte(data), nil
	}
	return os.ReadFile(data)
}

func loadTlsConfig(tc *config.TlsConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certBytes, err := resolveTlsMaterial(tc.Cert)
			if err != nil {
				return nil, fmt.Errorf("failed to read cert: %w", err)
			}
			keyBytes, err := resolveTlsMaterial(tc.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to read key: %w", err)
			}
			cert, err := tls.X509KeyPair(certBytes, keyBytes)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		MinVersion:   tls.VersionTLS13,
	}

	if tc.Ca != "" {
		caBytes, err := resolveTlsMaterial(tc.Ca)
		if err == nil {
			caPool := x509.NewCertPool()
			if caPool.AppendCertsFromPEM(caBytes) {
				tlsCfg.ClientCAs = caPool
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
	}

	return tlsCfg, nil
}

func (cp *ControlPlane) Start() error {
	var l net.Listener
	var err error

	cp.mu.Lock()
	tc := cp.tlsCfg
	socketPath := cp.socketPath
	port := cp.port
	cp.mu.Unlock()

	var tlsConfig *tls.Config
	var active bool
	if tc != nil {
		tlsCfg, tlsErr := loadTlsConfig(tc)
		if tlsErr != nil {
			audit.Logger.Error(fmt.Sprintf("Control Plane TLS initialization bypassed: %s. Control Plane will fallback to plaintext/HTTP.", tlsErr.Error()))
		} else {
			tlsConfig = tlsCfg
			active = true
		}
	}

	cp.mu.Lock()
	cp.tlsActive = active
	cp.mu.Unlock()

	if socketPath != "" {
		if _, err := os.Stat(socketPath); err == nil {
			_ = os.Remove(socketPath)
		}
		l, err = net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		_ = os.Chmod(socketPath, 0600)
		audit.Logger.System(fmt.Sprintf("Control Plane locked strictly to Unix Domain Socket at %s", socketPath))
	} else {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		l, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		protocol := "HTTP"
		if tlsConfig != nil {
			protocol = "HTTPS/mTLS"
		}
		audit.Logger.System(fmt.Sprintf("Control Plane active using %s on port %d", protocol, port))
	}

	if tlsConfig != nil {
		l = tls.NewListener(l, tlsConfig)
	}

	cp.listener = l

	server := &http.Server{
		Handler:           cp,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.Serve(l); err != nil && err != http.ErrServerClosed {
			audit.Logger.Error(fmt.Sprintf("Control Plane server execution fault: %s", err.Error()))
		}
	}()

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-cp.stopChan
			cancel()
		}()
		Streamer.Start(ctx)
	}()

	return nil
}

func (cp *ControlPlane) Stop() error {
	close(cp.stopChan)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.listener != nil {
		_ = cp.listener.Close()
		if cp.socketPath != "" {
			_ = os.Remove(cp.socketPath)
		}
	}
	return nil
}

func (cp *ControlPlane) verifyProofOfWork(nonce string, deviceHash string, payloadHash string) error {
	timeWindow := time.Now().Unix() / 300

	challenge := fmt.Sprintf("%s:%d:%s:%s", cp.blindIndexSalt, timeWindow, deviceHash, payloadHash)
	h := sha256.New()
	h.Write([]byte(challenge + nonce))
	hashStr := hex.EncodeToString(h.Sum(nil))

	if !strings.HasPrefix(hashStr, "0000") {
		return errors.New("Invalid Proof of Work Challenge")
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.currentPoWWindow != timeWindow {
		cp.currentPoWWindow = timeWindow
		cp.seenNonces = make(map[string]bool)
	}

	if cp.seenNonces[nonce] {
		return errors.New("Proof of Work challenge nonce already used")
	}

	cp.seenNonces[nonce] = true
	return nil
}

func (cp *ControlPlane) authenticate(r *http.Request, isMutation bool, bodyBytes []byte) (string, error) {
	apiKey := r.Header.Get("X-Api-Key")
	deviceId := r.Header.Get("X-Device-Id")
	nonce := r.Header.Get("X-Pow-Nonce")

	if apiKey == "" {
		return "", errors.New("Missing API Key")
	}

	mac := hmac.New(sha256.New, cp.apiKeySecret)
	mac.Write([]byte(apiKey))
	providedHash := hex.EncodeToString(mac.Sum(nil))

	expectedBuf := []byte(cp.expectedApiKeyHash)
	providedBuf := []byte(providedHash)

	if subtle.ConstantTimeCompare(expectedBuf, providedBuf) != 1 {
		return "", errors.New("Unauthorized Access")
	}

	if deviceId == "" {
		return "", errors.New("Authentication Validation Failed (Missing device id)")
	}

	macD := hmac.New(sha256.New, cp.deviceSecret)
	macD.Write([]byte(deviceId))
	deviceHash := hex.EncodeToString(macD.Sum(nil))

	if isMutation {
		if nonce == "" {
			return "", errors.New("Mutation endpoint requires x-pow-nonce header")
		}
		h := sha256.New()
		h.Write(bodyBytes)
		payloadHash := hex.EncodeToString(h.Sum(nil))

		if err := cp.verifyProofOfWork(nonce, deviceHash, payloadHash); err != nil {
			return "", err
		}
	}

	return deviceHash, nil
}

func (cp *ControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)

	sandboxSubnetsEnv := os.Getenv("OTTERGATE_SANDBOX_SUBNETS")
	if sandboxSubnetsEnv != "" {
		ip := net.ParseIP(clientIp)
		if ip != nil {
			for _, subnetStr := range strings.Split(sandboxSubnetsEnv, ",") {
				_, subnetNet, err := net.ParseCIDR(strings.TrimSpace(subnetStr))
				if err == nil && subnetNet.Contains(ip) {
					audit.Logger.Error(fmt.Sprintf("[SECURITY] Blocked Control Plane access attempt from sandboxed client IP: %s (matches subnet: %s)", clientIp, subnetStr))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"Security Violation: Sandboxed containers are strictly forbidden from accessing the Control Plane."}`))
					return
				}
			}
		}
	}

	method := r.Method
	w.Header().Set("Content-Type", "application/json")

	if r.URL.Path == "/metrics" {
		if method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(audit.Logger.GetMetricsPrometheus()))
		return
	}

	if r.URL.Path == "/healthz" {
		if method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"healthy","timestamp":%d}`, time.Now().Unix())))
		return
	}

	if r.URL.Path == "/" || r.URL.Path == "/dashboard" {
		if method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(DashboardHTML))
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		isMutation := method == "PUT" || method == "POST"
		var bodyBytes []byte

		if isMutation {
			limitReader := io.LimitReader(r.Body, 1048576)
			var err error
			bodyBytes, err = io.ReadAll(limitReader)
			if err != nil {
				audit.Logger.Error(fmt.Sprintf("Control Plane API Fault: HTTP 413 | Payload size limit exceeded | Client: %s", clientIp))
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(`{"error":"Payload size limit exceeded"}`))
				return
			}
		}

		deviceHash, err := cp.authenticate(r, isMutation, bodyBytes)
		if err != nil {
			statusCode := http.StatusUnauthorized
			if strings.Contains(err.Error(), "Proof of Work") {
				statusCode = http.StatusForbidden
			}
			audit.Logger.Error(fmt.Sprintf("Control Plane API Fault: HTTP %d | %s | Client: %s", statusCode, err.Error(), clientIp))
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"error":%q}`, err.Error())))
			return
		}

		if r.URL.Path == "/api/v1/logs" {
			if method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
			events := audit.GlobalBuffer.GetEvents()
			data, err := json.Marshal(events)
			if err != nil {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write(data)
			return
		}

		if r.URL.Path == "/api/v1/containers" {
			if method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
			IPToName.RLock()
			data, _ := json.Marshal(IPToName.Map)
			IPToName.RUnlock()
			_, _ = w.Write(data)
			return
		}

		if r.URL.Path == "/api/v1/controlplane-status" {
			if method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
			cp.mu.RLock()
			status := map[string]interface{}{
				"port":               cp.port,
				"socketPath":         cp.socketPath,
				"configFilePath":     cp.configFilePath,
				"expectedApiKeyHash": cp.expectedApiKeyHash,
				"blindIndexSalt":     cp.blindIndexSalt,
				"currentPoWWindow":   cp.currentPoWWindow,
				"seenNoncesCount":    len(cp.seenNonces),
				"subscribersCount":   len(cp.subscribers),
				"tlsEnabled":         cp.tlsActive,
			}
			cp.mu.RUnlock()
			data, _ := json.Marshal(status)
			_, _ = w.Write(data)
			return
		}

		if r.URL.Path == "/api/v1/pow-challenge" {
			if method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			payloadHash := r.URL.Query().Get("payload_hash")
			if payloadHash == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"Missing payload_hash query parameter"}`))
				return
			}
			timeWindow := time.Now().Unix() / 300
			challenge := fmt.Sprintf("%s:%d:%s:%s", cp.blindIndexSalt, timeWindow, deviceHash, payloadHash)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"challenge":%q}`, challenge)))
			return
		}

		if r.URL.Path == "/api/v1/config" {
			if method == "GET" {
				cp.mu.RLock()
				data, _ := json.Marshal(cp.cfg)
				cp.mu.RUnlock()

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				audit.Logger.HTTP(clientIp, "GET", "control-plane", r.URL.Path, 200, "Config retrieved")
				return
			}

			if method == "PUT" {
				newCfg, err := config.ParseServerConfig(bodyBytes)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(fmt.Sprintf(`{"error":%q}`, err.Error())))
					return
				}

				cp.mu.Lock()
				defer cp.mu.Unlock()

				for _, host := range newCfg.Hosts {
					if host.HttpProxy != nil && host.HttpProxy.Headers != nil {
						for k, v := range host.HttpProxy.Headers {
							if !crypto.IsEncrypted(v) {
								enc, err2 := crypto.EncryptSecret(v)
								if err2 == nil {
									host.HttpProxy.Headers[k] = enc
								}
							}
						}
					}
				}

				tempPath := fmt.Sprintf("%s.tmp.%d", cp.configFilePath, time.Now().UnixNano())
				tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"failed to create persistent temp file"}`))
					return
				}

				enc := json.NewEncoder(tempFile)
				enc.SetIndent("", "  ")
				if err := enc.Encode(newCfg); err != nil {
					tempFile.Close()
					_ = os.Remove(tempPath)
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"failed to serialize configuration"}`))
					return
				}
				tempFile.Close()

				if err := os.Rename(tempPath, cp.configFilePath); err != nil {
					_ = os.Remove(tempPath)
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"failed to atomically replace configuration file"}`))
					return
				}

				cp.cfg = newCfg

				for _, callback := range cp.subscribers {
					go func(cb func(*config.ServerConfig)) {
						defer func() { _ = recover() }()
						cb(newCfg)
					}(callback)
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"success":true,"timestamp":%d,"device":%q}`, time.Now().UnixMilli(), deviceHash)))
				audit.Logger.HTTP(clientIp, "PUT", "control-plane", r.URL.Path, 200, "Config updated")
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Endpoint Not Found"}`))
		return
	}
}