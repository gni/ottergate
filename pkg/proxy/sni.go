package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"ottergate/pkg/audit"
	"ottergate/pkg/config"
	"ottergate/pkg/firewall"
)

const (
	MaxClientHelloSize = 16384
	MaxTlsExtensions   = 50
)

type PrefixConn struct {
	net.Conn
	Prefix []byte
}

func (p *PrefixConn) Read(b []byte) (int, error) {
	if len(p.Prefix) > 0 {
		n := copy(b, p.Prefix)
		p.Prefix = p.Prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

type SniProxyService struct {
	mu                sync.Mutex
	cfg               *config.ServerConfig
	port              int
	idleTimeout       time.Duration
	tcpListener       net.Listener
	activeConnections map[net.Conn]bool
	stopChan          chan struct{}
	httpHandler       *HttpHandler
}

func NewSniProxyService(cfg *config.ServerConfig, httpHandler *HttpHandler) *SniProxyService {
	idle := 30 * time.Second
	if cfg.TcpIdleTimeoutMs > 0 {
		idle = time.Duration(cfg.TcpIdleTimeoutMs) * time.Millisecond
	}

	port := 443
	if cfg.HttpsPort != nil {
		port = *cfg.HttpsPort
	}

	return &SniProxyService{
		cfg:               cfg,
		port:              port,
		idleTimeout:       idle,
		activeConnections: make(map[net.Conn]bool),
		stopChan:          make(chan struct{}),
		httpHandler:       httpHandler,
	}
}

func (s *SniProxyService) UpdateConfig(newCfg *config.ServerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = newCfg
	if newCfg.HttpsPort != nil {
		s.port = *newCfg.HttpsPort
	}
	if newCfg.TcpIdleTimeoutMs > 0 {
		s.idleTimeout = time.Duration(newCfg.TcpIdleTimeoutMs) * time.Millisecond
	}
}

func (s *SniProxyService) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.tcpListener = l

	go s.acceptLoop()
	return nil
}

func (s *SniProxyService) Stop() error {
	close(s.stopChan)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}

	for conn := range s.activeConnections {
		_ = conn.Close()
	}

	return nil
}

func (s *SniProxyService) acceptLoop() {
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		s.mu.Lock()
		s.activeConnections[conn] = true
		s.mu.Unlock()

		go s.handleConnection(conn)
	}
}

func extractSNI(data []byte) (string, error) {
	if len(data) < 6 || data[0] != 0x16 || data[5] != 0x01 {
		return "", errors.New("not a TLS ClientHello")
	}

	offset := 43
	if offset >= len(data) {
		return "", errors.New("TLS ClientHello out of bounds")
	}

	sessionIdLength := int(data[offset])
	offset += 1 + sessionIdLength
	if offset >= len(data) {
		return "", errors.New("TLS ClientHello out of bounds")
	}

	if offset+2 > len(data) {
		return "", errors.New("TLS ClientHello out of bounds")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2 + cipherSuitesLength
	if offset >= len(data) {
		return "", errors.New("TLS ClientHello out of bounds")
	}

	compressionMethodsLength := int(data[offset])
	offset += 1 + compressionMethodsLength
	if offset+2 > len(data) {
		return "", errors.New("TLS ClientHello out of bounds")
	}

	extensionsLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	extensionsEnd := offset + extensionsLength
	if extensionsEnd > len(data) {
		return "", errors.New("TLS ClientHello out of bounds")
	}

	extCount := 0
	for offset < extensionsEnd && offset+4 <= len(data) {
		if extCount > MaxTlsExtensions {
			return "", errors.New("SNI Parser bounded due to MAX_TLS_EXTENSIONS boundary hit")
		}
		extCount++

		extType := binary.BigEndian.Uint16(data[offset:])
		extLength := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4

		if extType == 0x0000 {
			extEnd := offset + extLength
			if extEnd > extensionsEnd || extEnd > len(data) {
				return "", errors.New("SNI extension out of bounds")
			}

			sniOffset := offset
			if sniOffset+2 > extEnd {
				return "", errors.New("SNI extension out of bounds")
			}
			sniOffset += 2

			if sniOffset+1 > extEnd {
				return "", errors.New("SNI extension out of bounds")
			}
			nameType := data[sniOffset]

			if nameType == 0 {
				sniOffset += 1
				if sniOffset+2 > extEnd {
					return "", errors.New("SNI extension out of bounds")
				}
				nameLength := int(binary.BigEndian.Uint16(data[sniOffset:]))
				sniOffset += 2
				if sniOffset+nameLength > extEnd {
					return "", errors.New("SNI extension out of bounds")
				}
				return string(data[sniOffset : sniOffset+nameLength]), nil
			}
		}
		offset += extLength
	}

	return "", errors.New("no SNI extension found")
}

func (s *SniProxyService) findHostConfig(cfg *config.ServerConfig, hostname string) (config.HostConfig, bool) {
	normalizedName := strings.ToLower(strings.TrimSuffix(hostname, "."))
	if val, ok := cfg.Hosts[normalizedName]; ok {
		return val, true
	}

	labels := strings.Split(normalizedName, ".")
	for i := 0; i < len(labels)-1; i++ {
		wildcardKey := "*." + strings.Join(labels[i:], ".")
		if val, ok := cfg.Hosts[wildcardKey]; ok {
			return val, true
		}
	}

	return config.HostConfig{}, false
}

func (s *SniProxyService) resolveHost(hostname string, cfg *config.ServerConfig) ([]string, error) {
	hostConfig, ok := s.findHostConfig(cfg, hostname)
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

func (s *SniProxyService) handleConnection(clientSocket net.Conn) {
	isHandledOff := false
	defer func() {
		if !isHandledOff {
			clientSocket.Close()
		}
		s.mu.Lock()
		delete(s.activeConnections, clientSocket)
		s.mu.Unlock()
	}()

	clientIp, _, _ := net.SplitHostPort(clientSocket.RemoteAddr().String())
	var upstreamSocket net.Conn
	isHandled := false

	_ = clientSocket.SetDeadline(time.Now().Add(s.idleTimeout))

	absoluteHandshakeTimeout := time.AfterFunc(5*time.Second, func() {
		s.mu.Lock()
		handled := isHandled
		s.mu.Unlock()
		if !handled {
			audit.Logger.HTTP(clientIp, "TLS", "UNKNOWN", fmt.Sprintf(":%d", s.port), 408, "Dropped: ClientHello absolute timeout (Slowloris)")
			if !isHandledOff {
				_ = clientSocket.Close()
			}
		}
	})
	defer absoluteHandshakeTimeout.Stop()

	headerBuf := make([]byte, 5)
	if _, err := io.ReadFull(clientSocket, headerBuf); err != nil {
		return
	}

	s.mu.Lock()
	isHandled = true
	absoluteHandshakeTimeout.Stop()
	s.mu.Unlock()

	if headerBuf[0] != 0x16 {
		audit.Logger.HTTP(clientIp, "TLS", "UNKNOWN", fmt.Sprintf(":%d", s.port), 400, "Dropped: Not a TLS Handshake record")
		return
	}

	recordLength := binary.BigEndian.Uint16(headerBuf[3:5])
	if recordLength > MaxClientHelloSize {
		audit.Logger.HTTP(clientIp, "TLS", "UNKNOWN", fmt.Sprintf(":%d", s.port), 400, "Dropped: Overlong TLS Record length")
		return
	}

	payloadBuf := make([]byte, recordLength)
	if _, err := io.ReadFull(clientSocket, payloadBuf); err != nil {
		return
	}

	clientHelloBytes := append(headerBuf, payloadBuf...)
	sni, err := extractSNI(clientHelloBytes)
	if err != nil {
		audit.Logger.HTTP(clientIp, "TLS", "UNKNOWN", fmt.Sprintf(":%d", s.port), 400, "Dropped: No SNI detected")
		return
	}

	s.mu.Lock()
	currCfg := s.cfg
	s.mu.Unlock()

	fw := currCfg.Firewall

	tryTunnel := func() error {
		if firewall.Engine.EvaluateDomain(sni, fw) == "DENY" {
			return errors.New("domain blocked by Firewall policy")
		}

		hostConfig, hasHost := s.findHostConfig(currCfg, sni)
		portConfig := hostConfig
		if !hasHost {
			portConfig = currCfg.Hosts["*"]
		}

		if portConfig.HttpProxy != nil && portConfig.HttpProxy.Enabled {
			if currCfg.Tls == nil {
				return errors.New("L7 HTTPS termination requires a global TLS certificate configured")
			}
			tlsCfg, err := loadTlsConfig(currCfg.Tls)
			if err != nil {
				return fmt.Errorf("TLS load fault: %w", err)
			}

			prefixConn := &PrefixConn{
				Conn:   clientSocket,
				Prefix: clientHelloBytes,
			}
			tlsConn := tls.Server(prefixConn, tlsCfg)

			select {
			case s.httpHandler.VirtualListener.conns <- tlsConn:
				isHandledOff = true
				audit.Logger.HTTP(clientIp, "TLS-TERM", sni, fmt.Sprintf(":%d", s.port), 200, "L7 Decrypted -> Virtual HTTP Router")
			case <-time.After(3 * time.Second):
				_ = tlsConn.Close()
				return errors.New("Virtual listener capacity saturated. Connection dropped via resource constraint boundary.")
			}
			return nil
		}

		var targetIps []string
		if portConfig.TlsProxy != nil && portConfig.TlsProxy.TargetIp != "" {
			targetIps = []string{portConfig.TlsProxy.TargetIp}
		} else if hasHost {
			for _, r := range hostConfig.Records {
				if r.Type == "A" || r.Type == "AAAA" {
					targetIps = append(targetIps, r.Address)
				}
			}
		}

		if len(targetIps) == 0 {
			ips, err := s.resolveHost(sni, currCfg)
			if err != nil {
				return fmt.Errorf("resolution fault on upstream: %w", err)
			}
			targetIps = ips
		}

		if len(targetIps) == 0 {
			return errors.New("NXDOMAIN on upstream resolution")
		}

		targetIp := targetIps[0]

		if firewall.Engine.EvaluateOutbound(targetIp, fw) == "DENY" {
			return fmt.Errorf("Target IP %s blocked by Strict SSRF proxy policy", targetIp)
		}

		if firewall.Engine.EvaluateIp(targetIp, fw) == "DENY" {
			return fmt.Errorf("Target IP %s blocked by Firewall policy", targetIp)
		}

		targetPort := 443
		if portConfig.TlsProxy != nil && portConfig.TlsProxy.TargetPort != 0 {
			targetPort = portConfig.TlsProxy.TargetPort
		}

		audit.Logger.HTTP(clientIp, "TLS-SNI", sni, fmt.Sprintf(":%d", s.port), 200, fmt.Sprintf("Tunneled to %s:%d", targetIp, targetPort))

		targetUrlForProxy := &url.URL{
			Scheme: "https",
			Host:   fmt.Sprintf("%s:%d", sni, targetPort),
		}
		proxyURL, err := s.httpHandler.getUpstreamProxy(targetUrlForProxy)

		var uSocket net.Conn
		if err == nil && proxyURL != nil {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			uSocket, err = dialer.Dial("tcp", proxyURL.Host)
			if err != nil {
				return err
			}
			connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", sni, targetPort, sni, targetPort)
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
			destAddr := fmt.Sprintf("%s:%d", targetIp, targetPort)
			dialer := net.Dialer{Timeout: 5 * time.Second}
			uSocket, err = dialer.Dial("tcp", destAddr)
			if err != nil {
				return err
			}
		}
		upstreamSocket = uSocket

		s.mu.Lock()
		s.activeConnections[upstreamSocket] = true
		s.mu.Unlock()
		defer func() {
			upstreamSocket.Close()
			s.mu.Lock()
			delete(s.activeConnections, upstreamSocket)
			s.mu.Unlock()
		}()

		_ = upstreamSocket.SetDeadline(time.Now().Add(s.idleTimeout))

		if _, err := upstreamSocket.Write(clientHelloBytes); err != nil {
			return err
		}

		errChan := make(chan error, 2)
		go func() {
			_, err := io.Copy(upstreamSocket, clientSocket)
			errChan <- err
		}()
		go func() {
			_, err := io.Copy(clientSocket, upstreamSocket)
			errChan <- err
		}()

		<-errChan
		return nil
	}

	if err := tryTunnel(); err != nil {
		if !isHandledOff {
			audit.Logger.HTTP(clientIp, "TLS-SNI", sni, fmt.Sprintf(":%d", s.port), 403, fmt.Sprintf("Blocked: %s", err.Error()))
		}
	}
}