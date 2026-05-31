package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type ConfigValidationError struct {
	Msg string
}

func (e ConfigValidationError) Error() string {
	return e.Msg
}

var (
	labelRegex      = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)
	headerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
)

func IsValidHostname(hostname string) bool {
	if len(hostname) > 253 || len(hostname) == 0 {
		return false
	}
	parts := strings.Split(hostname, ".")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || !labelRegex.MatchString(part) {
			return false
		}
	}
	return true
}

func IsValidIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

func IsValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return ConfigValidationError{Msg: fmt.Sprintf("invalid port: %d (must be 1-65535)", port)}
	}
	return nil
}

func ValidateDnsRecord(r DnsRecord) error {
	switch r.Type {
	case "A":
		if !IsValidIPv4(r.Address) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid IPv4 address: %s", r.Address)}
		}
	case "AAAA":
		if !IsValidIPv6(r.Address) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid IPv6 address: %s", r.Address)}
		}
	case "CNAME", "NS", "PTR":
		if !IsValidHostname(r.Target) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid hostname target for %s: %s", r.Type, r.Target)}
		}
	case "TXT":
		if len(r.Data) == 0 {
			return ConfigValidationError{Msg: "TXT record must contain data"}
		}
		if len(r.Data) > 128 {
			return ConfigValidationError{Msg: "TXT record chunks density exceeds allocation boundary policy"}
		}
		totalLen := 0
		for _, d := range r.Data {
			if len(d) > 255 {
				return ConfigValidationError{Msg: "TXT record data chunk exceeds 255 bytes"}
			}
			if strings.ContainsAny(d, "\r\n") {
				return ConfigValidationError{Msg: "TXT record data contains CRLF"}
			}
			totalLen += len(d)
		}
		if totalLen > 2048 {
			return ConfigValidationError{Msg: "aggregate TXT record data size exceeds 2048 bytes"}
		}
	case "MX":
		if !IsValidHostname(r.Exchange) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid MX exchange: %s", r.Exchange)}
		}
		if r.Priority == nil || *r.Priority < 0 || *r.Priority > 65535 {
			return ConfigValidationError{Msg: "invalid MX priority"}
		}
	case "SRV":
		if !IsValidHostname(r.Target) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid SRV target: %s", r.Target)}
		}
		if r.Priority == nil || *r.Priority < 0 || *r.Priority > 65535 {
			return ConfigValidationError{Msg: "invalid SRV priority"}
		}
		if r.Weight == nil || *r.Weight < 0 || *r.Weight > 65535 {
			return ConfigValidationError{Msg: "invalid SRV weight"}
		}
		if r.Port == nil {
			return ConfigValidationError{Msg: "invalid SRV port"}
		}
		if err := ValidatePort(*r.Port); err != nil {
			return err
		}
	default:
		return ConfigValidationError{Msg: fmt.Sprintf("unsupported DNS record type: %s", r.Type)}
	}
	return nil
}

func ValidateTls(tls *TlsConfig) error {
	if tls == nil {
		return nil
	}
	if len(tls.Cert) == 0 {
		return ConfigValidationError{Msg: "TLS cert cannot be empty"}
	}
	if len(tls.Key) == 0 {
		return ConfigValidationError{Msg: "TLS key cannot be empty"}
	}
	if tls.ServerName != "" && !IsValidHostname(tls.ServerName) {
		return ConfigValidationError{Msg: fmt.Sprintf("invalid TLS serverName: %s", tls.ServerName)}
	}
	return nil
}

func ValidateHttpProxy(hp *HttpProxyConfig) error {
	if hp == nil {
		return nil
	}
	if hp.Enabled {
		if len(hp.Upstream) == 0 {
			return ConfigValidationError{Msg: "HTTP proxy requires 'upstream' URL when enabled"}
		}
		if strings.ContainsAny(hp.Upstream, "\r\n") {
			return ConfigValidationError{Msg: "HTTP proxy upstream URL contains CRLF"}
		}
		if len(hp.Upstream) > 8192 {
			return ConfigValidationError{Msg: "HTTP proxy upstream URL too long"}
		}
	}
	if len(hp.Headers) > 64 {
		return ConfigValidationError{Msg: "HTTP proxy metadata boundary capacity exceeded"}
	}
	for k, v := range hp.Headers {
		if len(k) > 256 || !headerNameRegex.MatchString(k) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid proxy header name: %s", k)}
		}
		if strings.ContainsAny(v, "\r\n") {
			return ConfigValidationError{Msg: fmt.Sprintf("proxy header %s contains CRLF", k)}
		}
		if len(v) > 8192 {
			return ConfigValidationError{Msg: fmt.Sprintf("proxy header %s is too long", k)}
		}
	}
	if hp.MaxRequestBodyBytes < 0 || hp.MaxRequestBodyBytes > 10485760 {
		return ConfigValidationError{Msg: "invalid maxRequestBodyBytes value (must be 0-10485760)"}
	}
	if hp.ClientTls != nil {
		if err := ValidateTls(hp.ClientTls); err != nil {
			return err
		}
	}
	return nil
}

func ValidateTlsProxy(tp *TlsProxyConfig) error {
	if tp == nil {
		return nil
	}
	if tp.TargetPort != 0 {
		if err := ValidatePort(tp.TargetPort); err != nil {
			return err
		}
	}
	if tp.TargetIp != "" {
		if !IsValidIPv4(tp.TargetIp) && !IsValidIPv6(tp.TargetIp) {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid TLS proxy target IP: %s", tp.TargetIp)}
		}
	}
	return nil
}

func ValidateRedirect(rc *RedirectConfig) error {
	if rc == nil {
		return nil
	}
	if !rc.Enabled {
		return nil
	}
	validCodes := map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}
	if !validCodes[rc.Code] {
		return ConfigValidationError{Msg: fmt.Sprintf("invalid redirect status code: %d", rc.Code)}
	}
	if strings.ContainsAny(rc.Target, "\r\n") {
		return ConfigValidationError{Msg: "redirect target URL contains CRLF"}
	}
	if len(rc.Target) > 8192 {
		return ConfigValidationError{Msg: "redirect target URL too long"}
	}
	parsed, err := url.Parse(rc.Target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ConfigValidationError{Msg: fmt.Sprintf("invalid redirect target URL: %s", rc.Target)}
	}
	return nil
}

func ValidateServerConfig(c *ServerConfig) error {
	if err := ValidatePort(c.Port); err != nil {
		return err
	}
	if c.HttpPort != nil {
		if err := ValidatePort(*c.HttpPort); err != nil {
			return err
		}
	}
	if c.HttpsPort != nil {
		if err := ValidatePort(*c.HttpsPort); err != nil {
			return err
		}
	}
	if c.DotPort != nil {
		if err := ValidatePort(*c.DotPort); err != nil {
			return err
		}
	}
	if c.DohPort != nil {
		if err := ValidatePort(*c.DohPort); err != nil {
			return err
		}
	}
	if c.FallbackDns != "" && !IsValidIPv4(c.FallbackDns) {
		return ConfigValidationError{Msg: fmt.Sprintf("invalid fallback DNS: %s (must be IPv4)", c.FallbackDns)}
	}
	if c.Tls != nil {
		if err := ValidateTls(c.Tls); err != nil {
			return err
		}
	}
	if c.Firewall != nil {
		f := c.Firewall
		if f.DefaultPolicy != "allow" && f.DefaultPolicy != "deny" {
			return ConfigValidationError{Msg: fmt.Sprintf("invalid firewall defaultPolicy: %s", f.DefaultPolicy)}
		}
		if len(f.AllowlistDomains) > 1000 || len(f.BlocklistDomains) > 1000 {
			return ConfigValidationError{Msg: "firewall domain metadata count policy limit violation"}
		}
		for _, d := range f.AllowlistDomains {
			if len(d) > 253 {
				return ConfigValidationError{Msg: "firewall domain too long"}
			}
		}
		for _, d := range f.BlocklistDomains {
			if len(d) > 253 {
				return ConfigValidationError{Msg: "firewall domain too long"}
			}
		}
		if len(f.AllowlistRanges) > 1000 || len(f.BlocklistRanges) > 1000 {
			return ConfigValidationError{Msg: "firewall network range capacity limit violation"}
		}
		for _, r := range f.AllowlistRanges {
			if _, _, err := net.ParseCIDR(r); err != nil {
				return ConfigValidationError{Msg: fmt.Sprintf("invalid firewall allowlist CIDR: %s", r)}
			}
		}
		for _, r := range f.BlocklistRanges {
			if _, _, err := net.ParseCIDR(r); err != nil {
				return ConfigValidationError{Msg: fmt.Sprintf("invalid firewall blocklist CIDR: %s", r)}
			}
		}
		if len(f.AllowlistIps) > 1000 || len(f.BlocklistIps) > 1000 {
			return ConfigValidationError{Msg: "firewall address registry size limit violation"}
		}
		for _, ip := range f.AllowlistIps {
			if !IsValidIPv4(ip) && !IsValidIPv6(ip) {
				return ConfigValidationError{Msg: fmt.Sprintf("invalid firewall allowlist IP: %s", ip)}
			}
		}
		for _, ip := range f.BlocklistIps {
			if !IsValidIPv4(ip) && !IsValidIPv6(ip) {
				return ConfigValidationError{Msg: fmt.Sprintf("invalid firewall blocklist IP: %s", ip)}
			}
		}
	}
	if c.ControlPlane != nil && c.ControlPlane.Port != 0 {
		if err := ValidatePort(c.ControlPlane.Port); err != nil {
			return err
		}
		if c.ControlPlane.Tls != nil {
			if err := ValidateTls(c.ControlPlane.Tls); err != nil {
				return err
			}
		}
	}

	if c.DnsCacheMaxSize < 1 || c.DnsCacheMaxSize > 100000 {
		if c.DnsCacheMaxSize == 0 {
			c.DnsCacheMaxSize = 1024
		} else {
			return ConfigValidationError{Msg: "invalid dnsCacheMaxSize (1-100000)"}
		}
	}
	if c.DnsCacheTtlMs < 0 || c.DnsCacheTtlMs > 3600000 {
		return ConfigValidationError{Msg: "invalid dnsCacheTtlMs (0-3600000)"}
	}
	if c.MaxTcpConnections < 1 || c.MaxTcpConnections > 10000 {
		if c.MaxTcpConnections == 0 {
			c.MaxTcpConnections = 100
		} else {
			return ConfigValidationError{Msg: "invalid maxTcpConnections (1-10000)"}
		}
	}
	if c.TcpIdleTimeoutMs < 1000 || c.TcpIdleTimeoutMs > 600000 {
		if c.TcpIdleTimeoutMs == 0 {
			c.TcpIdleTimeoutMs = 30000
		} else {
			return ConfigValidationError{Msg: "invalid tcpIdleTimeoutMs (1000-600000)"}
		}
	}
	if c.RateLimitMaxRequests < 0 || c.RateLimitMaxRequests > 100000 {
		return ConfigValidationError{Msg: "invalid rateLimitMaxRequests (0-100000)"}
	}
	if c.RateLimitWindowMs < 100 || c.RateLimitWindowMs > 60000 {
		if c.RateLimitWindowMs == 0 {
			c.RateLimitWindowMs = 1000
		} else {
			return ConfigValidationError{Msg: "invalid rateLimitWindowMs (100-60000)"}
		}
	}

	if len(c.Hosts) > 5000 {
		return ConfigValidationError{Msg: "hosts mapping allocation policy volume violation"}
	}

	normalizedHosts := make(map[string]HostConfig)
	for key, hc := range c.Hosts {
		normalized := strings.ToLower(strings.TrimSuffix(key, "."))
		if normalized != "*" {
			if strings.HasPrefix(normalized, "*.") {
				if !IsValidHostname(normalized[2:]) {
					return ConfigValidationError{Msg: fmt.Sprintf("invalid wildcard host in configuration key: %s", key)}
				}
			} else {
				if !IsValidHostname(normalized) {
					return ConfigValidationError{Msg: fmt.Sprintf("invalid hostname in configuration key: %s", key)}
				}
			}
		}
		if len(hc.Records) > 64 {
			return ConfigValidationError{Msg: "maximum records density capacity exceeded per routing label unit"}
		}
		for _, r := range hc.Records {
			if err := ValidateDnsRecord(r); err != nil {
				return err
			}
		}
		if err := ValidateHttpProxy(hc.HttpProxy); err != nil {
			return err
		}
		if err := ValidateTlsProxy(hc.TlsProxy); err != nil {
			return err
		}
		if err := ValidateRedirect(hc.Redirect); err != nil {
			return err
		}
		normalizedHosts[normalized] = hc
	}
	c.Hosts = normalizedHosts
	return nil
}

func ParseServerConfig(data []byte) (*ServerConfig, error) {
	var c ServerConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if err := ValidateServerConfig(&c); err != nil {
		return nil, err
	}
	return &c, nil
}