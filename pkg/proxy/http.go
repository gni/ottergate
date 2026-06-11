package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"ottergate/pkg/audit"
	"ottergate/pkg/config"
	"ottergate/pkg/crypto"
	"ottergate/pkg/firewall"
)

var (
	headerNameRegex = regexp.MustCompile("^[a-zA-Z0-9!#$%&'*+\\-.^_`|~]+$")
	hopByHopHeaders = []string{
		"connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
	}
	fingerprintHeadersToScrub = []string{
		"server", "via", "x-source", "x-powered-by", "x-generator",
		"cf-ray", "cf-cache-status", "x-cache", "x-cache-lookup",
		"x-drupal-cache", "x-varnish", "x-nextjs-cache", "x-fastly-request-id",
		"x-runtime", "x-version", "x-impl", "x-aspnet-version",
		"x-aspnetmvc-version", "microsoftofficewebserver", "x-powered-by-plesk",
		"x-pingback", "wp-super-cache", "x-ghost-version",
	}
)

type VirtualListener struct {
	mu     sync.Mutex
	conns  chan net.Conn
	closed bool
}

func NewVirtualListener() *VirtualListener {
	return &VirtualListener{conns: make(chan net.Conn, 1024)}
}

func (v *VirtualListener) Accept() (net.Conn, error) {
	c, ok := <-v.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (v *VirtualListener) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.closed {
		v.closed = true
		close(v.conns)
	}
	return nil
}

func (v *VirtualListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

type HttpHandler struct {
	mu              sync.RWMutex
	cfg             *config.ServerConfig
	port            int
	idleTimeout     time.Duration
	server          *http.Server
	VirtualListener *VirtualListener
	circuitBreakers map[string]*ProxyCircuitBreaker
	activeConns     map[net.Conn]bool
	loopSecret      string
	stopChan        chan struct{}
}

func NewHttpHandler(cfg *config.ServerConfig) *HttpHandler {
	port := 80
	if cfg.HttpPort != nil {
		port = *cfg.HttpPort
	}

	idle := 30 * time.Second
	if cfg.TcpIdleTimeoutMs > 0 {
		idle = time.Duration(cfg.TcpIdleTimeoutMs) * time.Millisecond
	}

	secretBytes := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, secretBytes)

	return &HttpHandler{
		cfg:             cfg,
		port:            port,
		idleTimeout:     idle,
		VirtualListener: NewVirtualListener(),
		circuitBreakers: make(map[string]*ProxyCircuitBreaker),
		activeConns:     make(map[net.Conn]bool),
		loopSecret:      hex.EncodeToString(secretBytes),
		stopChan:        make(chan struct{}),
	}
}

func (h *HttpHandler) UpdateConfig(newCfg *config.ServerConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = newCfg
	if newCfg.HttpPort != nil {
		h.port = *newCfg.HttpPort
	}
	if newCfg.TcpIdleTimeoutMs > 0 {
		h.idleTimeout = time.Duration(newCfg.TcpIdleTimeoutMs) * time.Millisecond
	}
}

func (h *HttpHandler) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", h.port)
	h.server = &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       h.idleTimeout,
	}

	h.server.ConnState = func(conn net.Conn, state http.ConnState) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if state == http.StateNew {
			h.activeConns[conn] = true
		} else if state == http.StateClosed {
			delete(h.activeConns, conn)
		}
	}

	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			audit.Logger.Error(fmt.Sprintf("HTTP Proxy server execution fault: %s", err.Error()))
		}
	}()

	virtServer := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       h.idleTimeout,
		ConnState:         h.server.ConnState,
	}

	go func() {
		if err := virtServer.Serve(h.VirtualListener); err != nil && err != http.ErrServerClosed {
			audit.Logger.Error(fmt.Sprintf("Virtual HTTPS server execution fault: %s", err.Error()))
		}
	}()

	return nil
}

func (h *HttpHandler) Stop() error {
	close(h.stopChan)
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.server != nil {
		_ = h.server.Close()
	}
	_ = h.VirtualListener.Close()

	for conn := range h.activeConns {
		_ = conn.Close()
	}

	return nil
}

func (h *HttpHandler) getCircuitBreaker(upstreamHost string) *ProxyCircuitBreaker {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.circuitBreakers) >= 10000 {
		for k := range h.circuitBreakers {
			delete(h.circuitBreakers, k)
			break
		}
	}

	cb, ok := h.circuitBreakers[upstreamHost]
	if !ok {
		cb = NewProxyCircuitBreaker(upstreamHost)
		h.circuitBreakers[upstreamHost] = cb
	}
	return cb
}

func (h *HttpHandler) normalizeUrlPath(urlStr string) string {
	return strings.TrimSuffix(urlStr, "?")
}

func (h *HttpHandler) generateLoopToken(urlStr string, clientIp string) string {
	target := h.normalizeUrlPath(urlStr)
	window := time.Now().Unix() / 60
	mac := hmac.New(sha256.New, []byte(h.loopSecret))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", target, clientIp, window)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *HttpHandler) verifyLoopToken(token string, urlStr string, clientIp string) bool {
	target := h.normalizeUrlPath(urlStr)
	window := time.Now().Unix() / 60

	mac0 := hmac.New(sha256.New, []byte(h.loopSecret))
	mac0.Write([]byte(fmt.Sprintf("%s:%s:%d", target, clientIp, window)))
	token0 := hex.EncodeToString(mac0.Sum(nil))

	mac1 := hmac.New(sha256.New, []byte(h.loopSecret))
	mac1.Write([]byte(fmt.Sprintf("%s:%s:%d", target, clientIp, window-1)))
	token1 := hex.EncodeToString(mac1.Sum(nil))

	return hmac.Equal([]byte(token), []byte(token0)) || hmac.Equal([]byte(token), []byte(token1))
}

func (h *HttpHandler) findWildcardHost(cfg *config.ServerConfig, hostname string) (config.HostConfig, bool) {
	normalizedName := strings.ToLower(strings.TrimSuffix(hostname, "."))
	labels := strings.Split(normalizedName, ".")

	for i := 0; i < len(labels)-1; i++ {
		suffix := strings.Join(labels[i:], ".")
		wildcardKey := "*." + suffix
		if val, ok := cfg.Hosts[wildcardKey]; ok {
			return val, true
		}
	}

	return config.HostConfig{}, false
}

func (h *HttpHandler) resolveHost(hostname string, cfg *config.ServerConfig) ([]string, error) {
	normalizedName := strings.ToLower(strings.TrimSuffix(hostname, "."))
	hostConfig, ok := cfg.Hosts[normalizedName]
	if !ok {
		wildConfig, ok2 := h.findWildcardHost(cfg, hostname)
		if ok2 {
			hostConfig = wildConfig
			ok = true
		}
	}

	if ok {
		var ips []string
		for _, r := range hostConfig.Records {
			if r.Type == "A" || r.Type == "AAAA" {
				ips = append(ips, r.Address)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}

	ips, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func (h *HttpHandler) validateTargetFirewall(targetUrl string, cfg *config.ServerConfig) ([]string, error) {
	parsed, err := url.Parse(targetUrl)
	if err != nil {
		return nil, err
	}

	host := parsed.Hostname()
	isLiteralIp := net.ParseIP(host) != nil

	fw := cfg.Firewall

	if fw != nil && !isLiteralIp {
		if firewall.Engine.EvaluateDomain(host, fw) == "DENY" {
			return nil, fmt.Errorf("Domain Blocked: '%s'", host)
		}
	}

	var targetIps []string
	if isLiteralIp {
		targetIps = []string{host}
	} else {
		ips, err := h.resolveHost(host, cfg)
		if err != nil {
			return nil, fmt.Errorf("Resolution Fault: '%s'", host)
		}
		targetIps = ips
	}

	if len(targetIps) == 0 {
		return nil, fmt.Errorf("NXDOMAIN: '%s'", host)
	}

	for _, ip := range targetIps {
		if firewall.Engine.EvaluateOutbound(ip, fw) == "DENY" {
			return nil, fmt.Errorf("Restricted IP: (%s)", ip)
		}
		if firewall.Engine.EvaluateIp(ip, fw) == "DENY" {
			return nil, fmt.Errorf("IP Blocked: %s", ip)
		}
	}

	return targetIps, nil
}

func sanitizeHeader(value string) (string, error) {
	if len(value) > 8192 {
		return "", errors.New("header value too long")
	}
	for _, r := range value {
		if r == '\r' || r == '\n' || r == '\t' {
			return "", errors.New("contains CR/LF/HT")
		}
		if r < 32 || r == 127 {
			return "", errors.New("contains control characters")
		}
	}
	return value, nil
}

func (h *HttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)

	h.mu.RLock()
	currCfg := h.cfg
	h.mu.RUnlock()

	providedLoopToken := r.Header.Get("X-Ottergate-Loop")
	reqUrl := r.URL.Path
	if r.URL.RawQuery != "" {
		reqUrl += "?" + r.URL.RawQuery
	}

	if providedLoopToken != "" {
		if h.verifyLoopToken(providedLoopToken, reqUrl, clientIp) {
			audit.Logger.HTTP(clientIp, r.Method, r.Host, reqUrl, 508, "Routing Loop Detected")
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusLoopDetected)
			_, _ = w.Write([]byte("<h1>508 Loop Detected</h1>"))
			return
		}
	}

	if r.Method == "CONNECT" {
		h.handleConnect(w, r, currCfg)
		return
	}

	h.handleRequest(w, r, currCfg)
}

func (h *HttpHandler) handleConnect(w http.ResponseWriter, r *http.Request, cfg *config.ServerConfig) {
	clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)
	targetUrl := r.RequestURI

	host, portStr, err := net.SplitHostPort(targetUrl)
	if err != nil {
		host = targetUrl
		portStr = "443"
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	clientSocket, _, err := hijacker.Hijack()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer clientSocket.Close()

	var srvSocket net.Conn

	tryTunnel := func() error {
		validatedIps, err := h.validateTargetFirewall(fmt.Sprintf("https://%s:%s", host, portStr), cfg)
		if err != nil {
			return err
		}
		targetIp := validatedIps[0]

		audit.Logger.HTTP(clientIp, "CONNECT", host, ":"+portStr, 200, "TCP Tunnel Established -> "+targetIp)

		_ = clientSocket.SetDeadline(time.Now().Add(h.idleTimeout))

		targetUrlForProxy := &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(host, portStr),
		}
		proxyURL, err := h.getUpstreamProxy(targetUrlForProxy)

		var uSocket net.Conn
		if err == nil && proxyURL != nil {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			uSocket, err = dialer.Dial("tcp", proxyURL.Host)
			if err != nil {
				return err
			}
			connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, portStr, host, portStr)
			_, err = uSocket.Write([]byte(connectReq))
			if err != nil {
				uSocket.Close()
				return err
			}
			respBuf := make([]byte, 4096)
			n, err := uSocket.Read(respBuf)
			if err != nil {
				uSocket.Close()
				return err
			}
			respStr := string(respBuf[:n])
			if !strings.Contains(respStr, "200") {
				uSocket.Close()
				return fmt.Errorf("upstream proxy returned: %s", strings.Split(respStr, "\r\n")[0])
			}
		} else {
			dialAddr := fmt.Sprintf("%s:%s", targetIp, portStr)
			dialer := net.Dialer{Timeout: 5 * time.Second}
			uSocket, err = dialer.Dial("tcp", dialAddr)
			if err != nil {
				return err
			}
		}
		srvSocket = uSocket

		_ = srvSocket.SetDeadline(time.Now().Add(h.idleTimeout))

		_, _ = clientSocket.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		errChan := make(chan error, 2)
		go func() {
			_, err := io.Copy(srvSocket, clientSocket)
			errChan <- err
		}()
		go func() {
			_, err := io.Copy(clientSocket, srvSocket)
			errChan <- err
		}()

		<-errChan
		return nil
	}

	if err := tryTunnel(); err != nil {
		audit.Logger.HTTP(clientIp, "CONNECT", host, ":"+portStr, 403, "Blocked by Firewall")
		_, _ = clientSocket.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}
	if srvSocket != nil {
		srvSocket.Close()
	}
}

func (h *HttpHandler) handleRequest(w http.ResponseWriter, r *http.Request, cfg *config.ServerConfig) {
	clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)
	reqMethod := r.Method
	reqUrl := r.RequestURI

	rawHost := r.Host
	hostname := rawHost
	if strings.Contains(rawHost, "[") {
		closingIdx := strings.Index(rawHost, "]")
		if closingIdx != -1 {
			hostname = rawHost[1:closingIdx]
		}
	} else {
		hostname = strings.Split(rawHost, ":")[0]
	}

	if hostname == "" {
		audit.Logger.HTTP(clientIp, reqMethod, "UNKNOWN", reqUrl, 400, "Missing Host Header")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Bad Request"))
		return
	}

	normalizedHost := strings.ToLower(strings.TrimSuffix(hostname, "."))
	hostConfig, ok := cfg.Hosts[normalizedHost]
	if !ok {
		wildConfig, ok2 := h.findWildcardHost(cfg, hostname)
		if ok2 {
			hostConfig = wildConfig
			ok = true
		}
	}

	if ok {
		if hostConfig.Redirect != nil && hostConfig.Redirect.Enabled {
			redirect := hostConfig.Redirect
			_, err := h.validateTargetFirewall(redirect.Target, cfg)
			if err != nil {
				audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by L3 Firewall")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, redirect.Code, redirect.Target)
			w.Header().Set("Location", redirect.Target)
			w.WriteHeader(redirect.Code)
			return
		}

		if hostConfig.HttpProxy != nil && hostConfig.HttpProxy.Enabled && hostConfig.HttpProxy.Upstream != "" {
			upstreamBase, err := url.Parse(hostConfig.HttpProxy.Upstream)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			validatedIps, err := h.validateTargetFirewall(upstreamBase.String(), cfg)
			if err != nil {
				audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by L3 Firewall")
				w.WriteHeader(http.StatusForbidden)
				return
			}

			targetIp := validatedIps[0]

			safePath := "/"
			parsedPath, err := url.Parse(reqUrl)
			if err == nil {
				safePath = parsedPath.Path
				if parsedPath.RawQuery != "" {
					safePath += "?" + parsedPath.RawQuery
				}
			}

			targetUrl, _ := url.Parse(upstreamBase.String())
			targetUrl.Path = safePath

			customReqHeaders := make(map[string]string)
			customResHeaders := make(map[string]string)

			for k, v := range hostConfig.HttpProxy.Headers {
				decrypted, err := crypto.DecryptSecret(v)
				if err == nil {
					sanitized, err2 := sanitizeHeader(decrypted)
					if err2 == nil {
						customReqHeaders[k] = sanitized
					}
				}
			}

			customResHeaders["X-Proxy"] = "ottergate"
			customResHeaders["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
			customResHeaders["X-Content-Type-Options"] = "nosniff"
			customResHeaders["X-Frame-Options"] = "DENY"
			customResHeaders["X-XSS-Protection"] = "1; mode=block"

			maxBodyBytes := int64(5242880)
			if hostConfig.HttpProxy.MaxRequestBodyBytes > 0 {
				maxBodyBytes = hostConfig.HttpProxy.MaxRequestBodyBytes
			}

			var clientTlsConfig *tls.Config
			if hostConfig.HttpProxy.ClientTls != nil {
				tlsCfg, err := loadTlsConfig(hostConfig.HttpProxy.ClientTls)
				if err != nil {
					audit.Logger.Error(fmt.Sprintf("Client TLS initialization for host proxy %s bypassed: %s", r.Host, err.Error()))
				} else {
					clientTlsConfig = tlsCfg
				}
			}

			h.doHttpProxy(
				w, r,
				targetUrl, targetIp,
				upstreamBase.Hostname(),
				clientIp,
				h.getCircuitBreaker(upstreamBase.Hostname()),
				targetUrl.String(),
				customReqHeaders, customResHeaders,
				maxBodyBytes,
				clientTlsConfig,
				hostConfig.HttpProxy.ForwardRequestBody,
				cfg,
			)
			return
		}
	}

	isLiteralIp := net.ParseIP(hostname) != nil
	fw := cfg.Firewall

	if isLiteralIp {
		if firewall.Engine.EvaluateIp(hostname, fw) == "DENY" {
			audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by IP Firewall")
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		if firewall.Engine.EvaluateDomain(hostname, fw) == "DENY" {
			audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by Domain Firewall")
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	var targetIp string
	if isLiteralIp {
		targetIp = hostname
	} else {
		ips, err := h.resolveHost(hostname, cfg)
		if err != nil || len(ips) == 0 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		targetIp = ips[0]
	}

	if firewall.Engine.EvaluateIp(targetIp, fw) == "DENY" {
		audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by IP Firewall")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if firewall.Engine.EvaluateOutbound(targetIp, fw) == "DENY" {
		audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by SSRF Policy")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	targetUrl, _ := url.Parse("http://" + rawHost + reqUrl)

	h.doHttpProxy(
		w, r,
		targetUrl, targetIp,
		hostname,
		clientIp,
		h.getCircuitBreaker(hostname),
		targetIp,
		nil, nil,
		5242880,
		nil,
		true,
		cfg,
	)
}

func (h *HttpHandler) doHttpProxy(
	w http.ResponseWriter, r *http.Request,
	targetUrl *url.URL, targetIp string,
	hostname string,
	clientIp string,
	breaker *ProxyCircuitBreaker,
	auditUrl string,
	customReqHeaders map[string]string,
	customResHeaders map[string]string,
	maxBodyBytes int64,
	clientTls *tls.Config,
	forwardBody bool,
	cfg *config.ServerConfig,
) {
	reqUrl := targetUrl.Path
	if targetUrl.RawQuery != "" {
		reqUrl += "?" + targetUrl.RawQuery
	}
	loopToken := h.generateLoopToken(reqUrl, clientIp)

	executeProxy := func() error {
		var bodyReader io.Reader
		if forwardBody && r.Method != "GET" && r.Method != "HEAD" {
			bodyReader = io.LimitReader(r.Body, maxBodyBytes)
		}

		destPort := targetUrl.Port()
		if destPort == "" {
			if targetUrl.Scheme == "https" {
				destPort = "443"
			} else {
				destPort = "80"
			}
		}

		dialAddr := fmt.Sprintf("%s:%s", targetIp, destPort)

		proxyURL, err := h.getUpstreamProxy(targetUrl)
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return proxyURL, nil
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: 5 * time.Second}
				if proxyURL != nil {
					return dialer.Dial(network, addr)
				}
				return dialer.Dial(network, dialAddr)
			},
			IdleConnTimeout: h.idleTimeout,
		}

		if targetUrl.Scheme == "https" {
			if clientTls == nil {
				clientTls = &tls.Config{}
			}
			if clientTls.ServerName == "" {
				clientTls.ServerName = hostname
			}
			transport.TLSClientConfig = clientTls
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetUrl.String(), bodyReader)
		if err != nil {
			return err
		}

		for k, vv := range r.Header {
			lowerK := strings.ToLower(k)
			isHop := false
			for _, hop := range hopByHopHeaders {
				if hop == lowerK {
					isHop = true
					break
				}
			}
			if !isHop {
				upReq.Header[k] = vv
			}
		}

		upReq.Header.Set("Host", targetUrl.Host)
		upReq.Header.Set("X-Ottergate-Loop", loopToken)

		if forwardBody && r.Method != "GET" && r.Method != "HEAD" {
			upReq.Header.Set("X-Body-Forwarded", "true")
			if r.ContentLength > 0 {
				upReq.Header.Set("X-Body-Size", fmt.Sprintf("%d", r.ContentLength))
			}
		}

		for k, v := range customReqHeaders {
			upReq.Header.Set(k, v)
		}

		resp, err := client.Do(upReq)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		for k, vv := range resp.Header {
			lowerK := strings.ToLower(k)
			isHop := false
			for _, hop := range hopByHopHeaders {
				if hop == lowerK {
					isHop = true
					break
				}
			}
			isScrubbed := false
			for _, scr := range fingerprintHeadersToScrub {
				if scr == lowerK {
					isScrubbed = true
					break
				}
			}
			if !isHop && !isScrubbed {
				w.Header()[k] = vv
			}
		}

		for k, v := range customResHeaders {
			w.Header().Set(k, v)
		}

		w.WriteHeader(resp.StatusCode)
		audit.Logger.HTTP(clientIp, r.Method, hostname, targetUrl.Path, resp.StatusCode, auditUrl)

		_, _ = io.Copy(w, resp.Body)
		return nil
	}

	err := breaker.Execute(executeProxy)
	if err != nil {
		h.handleHttpFault(err, clientIp, r.Method, hostname, reqUrl, w)
	}
}

func (h *HttpHandler) handleHttpFault(err error, clientIp string, reqMethod string, hostname string, reqUrl string, w http.ResponseWriter) {
	message := err.Error()

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Connection", "close")

	if strings.Contains(message, "Target Offline (Circuit Breaker OPEN)") {
		audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 503, "Circuit Breaker OPEN")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<h1>503 Service Unavailable (Circuit Broken)</h1>"))
		return
	}

	if strings.Contains(message, "Domain Blocked") || strings.Contains(message, "Restricted IP") || strings.Contains(message, "IP Blocked") || strings.Contains(message, "Resolution Fault") {
		audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked for Security (SSRF/Firewall)")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<h1>403 Forbidden</h1>"))
		return
	}

	if strings.Contains(message, "timeout") {
		audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 504, "Upstream Gateway Timeout")
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte("<h1>504 Gateway Timeout</h1>"))
		return
	}

	audit.Logger.HTTP(clientIp, reqMethod, hostname, reqUrl, 502, "Upstream Offline/Fault")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("<h1>502 Bad Gateway</h1>"))
}

func resolveTlsMaterial(data string) ([]byte, error) {
	if strings.Contains(data, "-----BEGIN") {
		return []byte(data), nil
	}
	return os.ReadFile(data)
}

func loadTlsConfig(tc *config.TlsConfig) (*tls.Config, error) {
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

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   tc.ServerName,
		MinVersion:   tls.VersionTLS12,
	}

	if tc.Ca != "" {
		caBytes, err := resolveTlsMaterial(tc.Ca)
		if err == nil {
			caPool := x509.NewCertPool()
			if caPool.AppendCertsFromPEM(caBytes) {
				tlsCfg.RootCAs = caPool
			}
		}
	}

	return tlsCfg, nil
}

func (h *HttpHandler) getUpstreamProxy(targetUrl *url.URL) (*url.URL, error) {
	h.mu.RLock()
	httpProxyStr := h.cfg.UpstreamHttpProxy
	httpsProxyStr := h.cfg.UpstreamHttpsProxy
	noProxyStr := h.cfg.UpstreamNoProxy
	h.mu.RUnlock()

	var proxyStr string
	if strings.ToLower(targetUrl.Scheme) == "https" {
		proxyStr = httpsProxyStr
	} else {
		proxyStr = httpProxyStr
	}

	// If not configured in the config file, fallback to environment variables
	if proxyStr == "" {
		return http.ProxyFromEnvironment(&http.Request{URL: targetUrl})
	}

	// Respect no-proxy ignores if configured
	if noProxyStr != "" {
		hostname := strings.ToLower(targetUrl.Hostname())
		ignored := false
		for _, pattern := range strings.Split(noProxyStr, ",") {
			pattern = strings.TrimSpace(strings.ToLower(pattern))
			if pattern == "" {
				continue
			}
			if pattern == "*" {
				ignored = true
				break
			}
			if strings.HasPrefix(pattern, ".") {
				if strings.HasSuffix(hostname, pattern) || hostname == pattern[1:] {
					ignored = true
					break
				}
			} else {
				if hostname == pattern || strings.HasSuffix(hostname, "."+pattern) {
					ignored = true
					break
				}
			}
		}
		if ignored {
			return nil, nil
		}
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, err
	}
	return proxyURL, nil
}