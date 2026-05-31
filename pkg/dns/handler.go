package dns

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"ottergate/pkg/audit"
	"ottergate/pkg/config"
	"ottergate/pkg/firewall"
)

const (
	MaxTcpBufferSize = 65535
	DnssecDoBit      = uint32(0x00008000)
)

type PendingUdpQuery struct {
	RemoteAddr    *net.UDPAddr
	OriginalID    uint16
	Timeout       *time.Timer
	ExpectedNames []string
	OriginalQuery []byte
}

type DnsHandler struct {
	mu           sync.Mutex
	server       *DevDnsServer
	cfg          *config.ServerConfig
	udpListener  *net.UDPConn
	tcpListener  net.Listener
	dotListener  net.Listener
	dohServer    *http.Server
	rateLimiter  *RateLimiter
	port         int
	fallbackDns  string
	maxTcpConns  int
	idleTimeout  time.Duration
	stopChan     chan struct{}

	activeTcpConns    map[net.Conn]bool
	upstreamTcpConns  map[net.Conn]bool
	pendingUdpQueries map[uint16]*PendingUdpQuery
	udpForwardsMu     sync.Mutex
	maxUdpForwards    int
}

func NewDnsHandler(server *DevDnsServer, cfg *config.ServerConfig) *DnsHandler {
	var rl *RateLimiter
	if cfg.RateLimitMaxRequests > 0 {
		rl = NewRateLimiter(cfg.RateLimitMaxRequests, cfg.RateLimitWindowMs, 100000)
	}

	idle := 30 * time.Second
	if cfg.TcpIdleTimeoutMs > 0 {
		idle = time.Duration(cfg.TcpIdleTimeoutMs) * time.Millisecond
	}

	maxTcp := 100
	if cfg.MaxTcpConnections > 0 {
		maxTcp = cfg.MaxTcpConnections
	}

	return &DnsHandler{
		server:            server,
		cfg:               cfg,
		rateLimiter:       rl,
		port:              cfg.Port,
		fallbackDns:       cfg.FallbackDns,
		maxTcpConns:       maxTcp,
		idleTimeout:       idle,
		stopChan:          make(chan struct{}),
		activeTcpConns:    make(map[net.Conn]bool),
		upstreamTcpConns:  make(map[net.Conn]bool),
		pendingUdpQueries: make(map[uint16]*PendingUdpQuery),
		maxUdpForwards:    2000,
	}
}

func (h *DnsHandler) UpdateConfig(newCfg *config.ServerConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cfg = newCfg
	h.port = newCfg.Port
	h.fallbackDns = newCfg.FallbackDns

	if newCfg.MaxTcpConnections > 0 {
		h.maxTcpConns = newCfg.MaxTcpConnections
	}
	if newCfg.TcpIdleTimeoutMs > 0 {
		h.idleTimeout = time.Duration(newCfg.TcpIdleTimeoutMs) * time.Millisecond
	}

	if h.rateLimiter != nil {
		h.rateLimiter.Destroy()
		h.rateLimiter = nil
	}
	if newCfg.RateLimitMaxRequests > 0 {
		h.rateLimiter = NewRateLimiter(newCfg.RateLimitMaxRequests, newCfg.RateLimitWindowMs, 100000)
	}
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

func (h *DnsHandler) Start() error {
	if err := h.startUdp(); err != nil {
		return err
	}
	if err := h.startTcp(); err != nil {
		_ = h.Stop()
		return err
	}

	h.mu.Lock()
	tc := h.cfg.Tls
	dotPort := 853
	if h.cfg.DotPort != nil {
		dotPort = *h.cfg.DotPort
	}
	dohPort := 8443
	if h.cfg.DohPort != nil {
		dohPort = *h.cfg.DohPort
	}
	h.mu.Unlock()

	if tc != nil {
		tlsCfg, err := loadTlsConfig(tc)
		if err != nil {
			audit.Logger.Error(fmt.Sprintf("[DNS-TLS] TLS initialization bypassed: %s. DoT/DoH will not be handled.", err.Error()))
		} else {
			dotAddr := fmt.Sprintf("0.0.0.0:%d", dotPort)
			l, err := tls.Listen("tcp", dotAddr, tlsCfg)
			if err != nil {
				_ = h.Stop()
				return err
			}
			h.dotListener = l
			audit.Logger.System(fmt.Sprintf("DoT (DNS over TLS) isolated boundary listening on port %d", dotPort))
			go h.acceptLoop(h.dotListener)

			dohAddr := fmt.Sprintf("0.0.0.0:%d", dohPort)
			mux := http.NewServeMux()
			mux.HandleFunc("/dns-query", h.handleDohRequest)
			h.dohServer = &http.Server{
				Addr:         dohAddr,
				Handler:      mux,
				TLSConfig:    tlsCfg,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
				IdleTimeout:  h.idleTimeout,
			}
			audit.Logger.System(fmt.Sprintf("DoH (DNS over HTTPS) isolated boundary listening on port %d", dohPort))
			go func() {
				if err := h.dohServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					audit.Logger.Error(fmt.Sprintf("DoH server execution fault: %s", err.Error()))
				}
			}()
		}
	}

	return nil
}

func (h *DnsHandler) Stop() error {
	close(h.stopChan)

	if h.rateLimiter != nil {
		h.rateLimiter.Destroy()
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.udpListener != nil {
		_ = h.udpListener.Close()
	}
	if h.tcpListener != nil {
		_ = h.tcpListener.Close()
	}
	if h.dotListener != nil {
		_ = h.dotListener.Close()
	}
	if h.dohServer != nil {
		_ = h.dohServer.Close()
	}

	h.udpForwardsMu.Lock()
	for _, pending := range h.pendingUdpQueries {
		pending.Timeout.Stop()
	}
	h.pendingUdpQueries = nil
	h.udpForwardsMu.Unlock()

	for conn := range h.activeTcpConns {
		_ = conn.Close()
	}
	for conn := range h.upstreamTcpConns {
		_ = conn.Close()
	}

	return nil
}

func (h *DnsHandler) startUdp() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", h.port))
	if err != nil {
		return err
	}
	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	_ = l.SetReadBuffer(1024 * 1024)
	h.udpListener = l

	if h.port == 0 {
		h.port = l.LocalAddr().(*net.UDPAddr).Port
	}

	go h.udpReadLoop()
	return nil
}

func (h *DnsHandler) startTcp() error {
	addr := fmt.Sprintf("0.0.0.0:%d", h.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.tcpListener = l
	go h.acceptLoop(h.tcpListener)
	return nil
}

func (h *DnsHandler) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-h.stopChan:
				return
			default:
				continue
			}
		}

		h.mu.Lock()
		if len(h.activeTcpConns) >= h.maxTcpConns {
			h.mu.Unlock()
			_ = conn.Close()
			continue
		}
		h.activeTcpConns[conn] = true
		h.mu.Unlock()

		go h.handleTcpConnection(conn)
	}
}

func (h *DnsHandler) isRateLimited(ip string) bool {
	if h.rateLimiter == nil {
		return false
	}
	return !h.rateLimiter.Allow(ip)
}

func (h *DnsHandler) isPrivateIp(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		b0 := ip4[0]
		b1 := ip4[1]
		return b0 == 127 || b0 == 10 || (b0 == 172 && b1 >= 16 && b1 <= 31) || (b0 == 192 && b1 == 168)
	}
	norm := strings.ToLower(ip.String())
	return norm == "::1" || strings.HasPrefix(norm, "fe80:") || strings.HasPrefix(norm, "fc00:") || strings.HasPrefix(norm, "fd")
}

func Apply0x20Encoding(originalQuery []byte) ([]byte, []string) {
	if len(originalQuery) < 12 {
		return originalQuery, nil
	}
	query := make([]byte, len(originalQuery))
	copy(query, originalQuery)

	qdcount := binary.BigEndian.Uint16(query[4:6])
	offset := 12

	for i := 0; i < int(qdcount); i++ {
		for offset < len(query) {
			length := query[offset]
			if length == 0 {
				offset++
				break
			}
			if (length & 0xc0) == 0xc0 {
				offset += 2
				break
			}

			offset++
			entropy := make([]byte, length)
			_, _ = io.ReadFull(rand.Reader, entropy)

			for j := 0; j < int(length); j++ {
				if offset+j >= len(query) {
					break
				}
				char := query[offset+j]
				if (char >= 0x41 && char <= 0x5a) || (char >= 0x61 && char <= 0x7a) {
					if entropy[j]%2 == 0 {
						char |= 0x20
					} else {
						char &^= 0x20
					}
					query[offset+j] = char
				}
			}
			offset += int(length)
		}
		if offset+4 <= len(query) {
			offset += 4
		}
	}

	questions := ExtractQuestions(query)
	var expectedNames []string
	for _, q := range questions {
		expectedNames = append(expectedNames, q.Name)
	}

	return query, expectedNames
}

func AppendEdns0DoBit(query []byte) []byte {
	if len(query) < 12 {
		return query
	}
	arcount := binary.BigEndian.Uint16(query[10:12])
	if arcount > 0 {
		return query
	}

	encoder := NewDnsWireFormat(nil)
	encoder.WriteBytes(query)
	binary.BigEndian.PutUint16(encoder.Buf[10:12], 1)

	encoder.WriteUint8(0)
	encoder.WriteUint16(config.DnsTypeOPT)
	encoder.WriteUint16(4096)
	encoder.WriteUint32(DnssecDoBit)
	encoder.WriteUint16(0)

	return encoder.Finish()
}

func ParseResolvedIpv4s(resp []byte) []string {
	var ips []string
	if len(resp) < 12 {
		return ips
	}
	defer func() {
		_ = recover()
	}()

	f := NewDnsWireFormat(resp)
	f.Offset = 4
	qd := f.readUint16()
	an := f.readUint16()
	f.Offset += 4

	for i := 0; i < int(qd); i++ {
		f.ReadDomainName()
		f.Offset += 4
	}

	for i := 0; i < int(an); i++ {
		f.ReadDomainName()
		qtype := f.readUint16()
		f.Offset += 6
		rdlen := f.readUint16()
		if qtype == config.DnsTypeA && rdlen == 4 {
			if f.Offset+4 <= len(resp) {
				ip := fmt.Sprintf("%d.%d.%d.%d", resp[f.Offset], resp[f.Offset+1], resp[f.Offset+2], resp[f.Offset+3])
				ips = append(ips, ip)
			}
		} else if qtype == config.DnsTypeAAAA && rdlen == 16 {
			if f.Offset+16 <= len(resp) {
				ipBytes := resp[f.Offset : f.Offset+16]
				ip := net.IP(ipBytes).String()
				ips = append(ips, ip)
			}
		}
		f.Offset += int(rdlen)
	}

	return ips
}

func (dw *DnsWireFormat) readUint16() uint16 {
	if dw.Offset+2 > len(dw.Buf) {
		dw.Offset = len(dw.Buf)
		return 0
	}
	val := binary.BigEndian.Uint16(dw.Buf[dw.Offset:])
	dw.Offset += 2
	return val
}

func (h *DnsHandler) resolveQueryAsync(query []byte, clientIp string) ([]byte, error) {
	resp := h.server.Resolve(query, clientIp)
	if resp != nil {
		if len(resp) > 0 {
			return resp, nil
		}
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}

	h.mu.Lock()
	fallback := h.fallbackDns
	fw := h.cfg.Firewall
	h.mu.Unlock()

	if fallback == "" {
		return h.server.GenerateErrorResponse(query, config.DnsRcodeNxDomain), nil
	}

	encoded, expectedNames := Apply0x20Encoding(query)
	dnssecQuery := AppendEdns0DoBit(encoded)

	rAddr, err := net.ResolveUDPAddr("udp", fallback+":53")
	if err != nil {
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}

	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write(dnssecQuery); err != nil {
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}

	msg := buf[:n]

	if !VerifyDnssecResponse(msg, expectedNames, fw) {
		audit.Logger.Error("Dropped upstream DoH fallback response: DNSSEC signature validation failed")
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}

	responseQuestions := ExtractQuestions(msg)
	valid0x20 := len(expectedNames) == len(responseQuestions)
	if valid0x20 {
		for i, name := range expectedNames {
			if responseQuestions[i].Name != name {
				valid0x20 = false
				break
			}
		}
	}

	if !valid0x20 {
		audit.Logger.Error("Dropped upstream DoH fallback response: 0x20 bit encoding mismatch (Spoofing Mitigation)")
		return h.server.GenerateErrorResponse(query, config.DnsRcodeServFail), nil
	}

	ips := ParseResolvedIpv4s(msg)
	var blockedIp string
	for _, ip := range ips {
		if firewall.Engine.EvaluateIp(ip, fw) == "DENY" {
			blockedIp = ip
			break
		}
	}

	questions := ExtractQuestions(query)
	var logQuestions []struct {
		Name string
		Type string
	}
	for _, q := range questions {
		logQuestions = append(logQuestions, struct {
			Name string
			Type string
		}{Name: q.Name, Type: h.server.toTypeString(q.Type)})
	}

	isLocal := len(logQuestions) > 0 && h.server.IsLocalHost(logQuestions[0].Name)
	if blockedIp != "" {
		audit.Logger.Firewall(clientIp, blockedIp, "DENY", "Upstream target IP blocked")
		audit.Logger.DNS(clientIp, logQuestions, config.DnsRcodeRefused, false, nil, isLocal)
		return h.server.GenerateErrorResponse(query, config.DnsRcodeRefused), nil
	}

	rcode := int(binary.BigEndian.Uint16(msg[2:4]) & 0xf)
	audit.Logger.DNS(clientIp, logQuestions, rcode, false, ParseResolvedIpv4s(msg), isLocal)
	return msg, nil
}

func (h *DnsHandler) handleDohRequest(w http.ResponseWriter, r *http.Request) {
	clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)
	if h.isRateLimited(clientIp) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	method := r.Method
	if r.URL.Path != "/dns-query" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var query []byte

	if method == "GET" {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(dnsParam) > 512 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var err error
		query, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			query, err = base64.URLEncoding.DecodeString(dnsParam)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	} else if method == "POST" {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}

		limitReader := io.LimitReader(r.Body, MaxTcpBufferSize)
		var err error
		query, err = io.ReadAll(limitReader)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if len(query) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp, err := h.resolveQueryAsync(query, clientIp)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(resp)))
	w.Header().Set("Cache-Control", "max-age=0")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (h *DnsHandler) udpReadLoop() {
	buf := make([]byte, 4096)
	for {
		n, raddr, err := h.udpListener.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-h.stopChan:
				return
			default:
				continue
			}
		}

		if h.isRateLimited(raddr.IP.String()) {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		go h.handleUdpMessage(data, raddr)
	}
}

func (h *DnsHandler) handleUdpMessage(data []byte, raddr *net.UDPAddr) {
	resp := h.server.Resolve(data, raddr.IP.String())
	if resp != nil {
		if len(resp) > 0 {
			_, _ = h.udpListener.WriteToUDP(resp, raddr)
		}
	} else {
		h.mu.Lock()
		fallback := h.fallbackDns
		h.mu.Unlock()

		if fallback != "" {
			h.forwardUdpQuery(data, raddr)
		} else {
			nx := h.server.GenerateErrorResponse(data, config.DnsRcodeNxDomain)
			_, _ = h.udpListener.WriteToUDP(nx, raddr)
		}
	}
}

func (h *DnsHandler) forwardUdpQuery(data []byte, raddr *net.UDPAddr) {
	h.mu.Lock()
	fallback := h.fallbackDns
	fw := h.cfg.Firewall
	h.mu.Unlock()

	if fallback == "" {
		return
	}

	clientIp := raddr.IP.String()

	if !h.isPrivateIp(clientIp) {
		allowed := false
		if fw != nil {
			for _, ip := range fw.AllowlistIps {
				if ip == clientIp {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			audit.Logger.System(fmt.Sprintf("Dropped UDP forward request from untrusted WAN IP: %s (Anti-Amplification)", clientIp))
			return
		}
	}

	h.udpForwardsMu.Lock()
	if len(h.pendingUdpQueries) >= h.maxUdpForwards {
		h.udpForwardsMu.Unlock()
		audit.Logger.System("Dropped UDP forward request: Concurrent connection limit reached")
		return
	}

	if len(data) < 2 {
		h.udpForwardsMu.Unlock()
		return
	}

	originalID := binary.BigEndian.Uint16(data[0:2])

	ephemeralBytes := make([]byte, 2)
	_, _ = io.ReadFull(rand.Reader, ephemeralBytes)
	ephemeralID := binary.BigEndian.Uint16(ephemeralBytes)

	for {
		if _, exists := h.pendingUdpQueries[ephemeralID]; !exists {
			break
		}
		_, _ = io.ReadFull(rand.Reader, ephemeralBytes)
		ephemeralID = binary.BigEndian.Uint16(ephemeralBytes)
	}

	encoded, expectedNames := Apply0x20Encoding(data)
	binary.BigEndian.PutUint16(encoded[0:2], ephemeralID)
	dnssecQuery := AppendEdns0DoBit(encoded)

	tAddress, err := net.ResolveUDPAddr("udp", fallback+":53")
	if err != nil {
		h.udpForwardsMu.Unlock()
		return
	}

	timeout := time.AfterFunc(3*time.Second, func() {
		h.udpForwardsMu.Lock()
		pending, exists := h.pendingUdpQueries[ephemeralID]
		if exists {
			delete(h.pendingUdpQueries, ephemeralID)
		}
		h.udpForwardsMu.Unlock()

		if exists {
			ref := h.server.GenerateErrorResponse(data, config.DnsRcodeServFail)
			_, _ = h.udpListener.WriteToUDP(ref, pending.RemoteAddr)
		}
	})

	h.pendingUdpQueries[ephemeralID] = &PendingUdpQuery{
		RemoteAddr:    raddr,
		OriginalID:    originalID,
		Timeout:       timeout,
		ExpectedNames: expectedNames,
		OriginalQuery: data,
	}
	h.udpForwardsMu.Unlock()

	go func() {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		conn, err := dialer.Dial("udp", tAddress.String())
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(dnssecQuery); err != nil {
			return
		}

		respBuf := make([]byte, 4096)
		n, err := conn.Read(respBuf)
		if err != nil {
			return
		}

		msg := make([]byte, n)
		copy(msg, respBuf[:n])
		h.handleUdpUpstreamResponse(msg)
	}()
}

func (h *DnsHandler) handleUdpUpstreamResponse(msg []byte) {
	if len(msg) < 2 {
		return
	}
	ephemeralID := binary.BigEndian.Uint16(msg[0:2])

	h.udpForwardsMu.Lock()
	pending, exists := h.pendingUdpQueries[ephemeralID]
	if exists {
		delete(h.pendingUdpQueries, ephemeralID)
	}
	h.udpForwardsMu.Unlock()

	if !exists {
		return
	}

	pending.Timeout.Stop()

	h.mu.Lock()
	fw := h.cfg.Firewall
	h.mu.Unlock()

	if !VerifyDnssecResponse(msg, pending.ExpectedNames, fw) {
		audit.Logger.Error("Dropped upstream UDP response: DNSSEC signature validation failed")
		return
	}

	responseQuestions := ExtractQuestions(msg)
	valid0x20 := len(pending.ExpectedNames) == len(responseQuestions)
	if valid0x20 {
		for i, name := range pending.ExpectedNames {
			if responseQuestions[i].Name != name {
				valid0x20 = false
				break
			}
		}
	}

	if !valid0x20 {
		audit.Logger.Error("Dropped upstream UDP response: 0x20 bit encoding mismatch (Spoofing Mitigation)")
		return
	}

	restoredMsg := make([]byte, len(msg))
	copy(restoredMsg, msg)
	binary.BigEndian.PutUint16(restoredMsg[0:2], pending.OriginalID)

	ips := ParseResolvedIpv4s(restoredMsg)
	var blockedIp string
	for _, ip := range ips {
		if firewall.Engine.EvaluateIp(ip, fw) == "DENY" {
			blockedIp = ip
			break
		}
	}

	questions := ExtractQuestions(restoredMsg)
	var logQuestions []struct {
		Name string
		Type string
	}
	for _, q := range questions {
		logQuestions = append(logQuestions, struct {
			Name string
			Type string
		}{Name: q.Name, Type: h.server.toTypeString(q.Type)})
	}

	clientIp := pending.RemoteAddr.IP.String()

	isLocal := len(logQuestions) > 0 && h.server.IsLocalHost(logQuestions[0].Name)
	if blockedIp != "" {
		audit.Logger.Firewall(clientIp, blockedIp, "DENY", "Upstream target IP blocked")
		audit.Logger.DNS(clientIp, logQuestions, config.DnsRcodeRefused, false, nil, isLocal)
		ref := h.server.GenerateErrorResponse(restoredMsg, config.DnsRcodeRefused)
		_, _ = h.udpListener.WriteToUDP(ref, pending.RemoteAddr)
	} else {
		rcode := int(binary.BigEndian.Uint16(restoredMsg[2:4]) & 0xf)
		audit.Logger.DNS(clientIp, logQuestions, rcode, false, ParseResolvedIpv4s(restoredMsg), isLocal)
		_, _ = h.udpListener.WriteToUDP(restoredMsg, pending.RemoteAddr)
	}
}

func (h *DnsHandler) handleTcpConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		h.mu.Lock()
		delete(h.activeTcpConns, conn)
		h.mu.Unlock()
	}()

	clientIp, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if h.isRateLimited(clientIp) {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(h.idleTimeout))

	lengthBuf := make([]byte, 2)
	for {
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return
		}

		length := binary.BigEndian.Uint16(lengthBuf)
		if length == 0 || length > MaxTcpBufferSize {
			return
		}

		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		resp := h.server.Resolve(query, clientIp)
		if resp != nil {
			if len(resp) > 0 {
				prefixed := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(prefixed[0:2], uint16(len(resp)))
				copy(prefixed[2:], resp)
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(prefixed); err != nil {
					return
				}
			} else {
				return
			}
		} else {
			h.mu.Lock()
			fallback := h.fallbackDns
			h.mu.Unlock()

			if fallback != "" {
				h.forwardTcpQuery(query, conn, clientIp)
				return
			} else {
				nx := h.server.GenerateErrorResponse(query, config.DnsRcodeNxDomain)
				prefixed := make([]byte, 2+len(nx))
				binary.BigEndian.PutUint16(prefixed[0:2], uint16(len(nx)))
				copy(prefixed[2:], nx)
				_, _ = conn.Write(prefixed)
				return
			}
		}

		_ = conn.SetDeadline(time.Now().Add(h.idleTimeout))
	}
}

func (h *DnsHandler) forwardTcpQuery(query []byte, clientConn net.Conn, clientIp string) {
	h.mu.Lock()
	fallback := h.fallbackDns
	fw := h.cfg.Firewall
	h.mu.Unlock()

	encoded, expectedNames := Apply0x20Encoding(query)
	dnssecQuery := AppendEdns0DoBit(encoded)

	conn, err := net.DialTimeout("tcp", fallback+":53", 3*time.Second)
	if err != nil {
		h.sendTcpError(clientConn, query, config.DnsRcodeServFail)
		return
	}
	defer conn.Close()

	h.mu.Lock()
	h.upstreamTcpConns[conn] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.upstreamTcpConns, conn)
		h.mu.Unlock()
	}()

	_ = conn.SetDeadline(time.Now().Add(h.idleTimeout))

	prefixedQuery := make([]byte, 2+len(dnssecQuery))
	binary.BigEndian.PutUint16(prefixedQuery[0:2], uint16(len(dnssecQuery)))
	copy(prefixedQuery[2:], dnssecQuery)

	if _, err := conn.Write(prefixedQuery); err != nil {
		h.sendTcpError(clientConn, query, config.DnsRcodeServFail)
		return
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		h.sendTcpError(clientConn, query, config.DnsRcodeServFail)
		return
	}

	length := binary.BigEndian.Uint16(lengthBuf)
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		h.sendTcpError(clientConn, query, config.DnsRcodeServFail)
		return
	}

	if !VerifyDnssecResponse(resp, expectedNames, fw) {
		audit.Logger.Error("Dropped upstream TCP response: DNSSEC signature validation failed")
		h.sendTcpError(clientConn, query, config.DnsRcodeServFail)
		return
	}

	responseQuestions := ExtractQuestions(resp)
	valid0x20 := len(expectedNames) == len(responseQuestions)
	if valid0x20 {
		for i, name := range expectedNames {
			if responseQuestions[i].Name != name {
				valid0x20 = false
				break
			}
		}
	}

	if !valid0x20 {
		audit.Logger.Error("Dropped upstream TCP response: 0x20 bit encoding mismatch (Spoofing Mitigation)")
		h.sendTcpError(clientConn, query, config.DnsRcodeServFail)
		return
	}

	ips := ParseResolvedIpv4s(resp)
	var blockedIp string
	for _, ip := range ips {
		if firewall.Engine.EvaluateIp(ip, fw) == "DENY" {
			blockedIp = ip
			break
		}
	}

	questions := ExtractQuestions(query)
	var logQuestions []struct {
		Name string
		Type string
	}
	for _, q := range questions {
		logQuestions = append(logQuestions, struct {
			Name string
			Type string
		}{Name: q.Name, Type: h.server.toTypeString(q.Type)})
	}

	isLocal := len(logQuestions) > 0 && h.server.IsLocalHost(logQuestions[0].Name)
	if blockedIp != "" {
		audit.Logger.Firewall(clientIp, blockedIp, "DENY", "Upstream target IP blocked")
		audit.Logger.DNS(clientIp, logQuestions, config.DnsRcodeRefused, false, nil, isLocal)
		h.sendTcpError(clientConn, query, config.DnsRcodeRefused)
		return
	}

	rcode := int(binary.BigEndian.Uint16(resp[2:4]) & 0xf)
	audit.Logger.DNS(clientIp, logQuestions, rcode, false, ParseResolvedIpv4s(resp), isLocal)

	origID := binary.BigEndian.Uint16(query[0:2])
	binary.BigEndian.PutUint16(resp[0:2], origID)

	prefixedResp := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(prefixedResp[0:2], uint16(len(resp)))
	copy(prefixedResp[2:], resp)

	_, _ = clientConn.Write(prefixedResp)
}

func (h *DnsHandler) sendTcpError(conn net.Conn, query []byte, rcode int) {
	nx := h.server.GenerateErrorResponse(query, rcode)
	prefixed := make([]byte, 2+len(nx))
	binary.BigEndian.PutUint16(prefixed[0:2], uint16(len(nx)))
	copy(prefixed[2:], nx)
	_, _ = conn.Write(prefixed)
}

func (h *DnsHandler) GetPort() int {
	return h.port
}