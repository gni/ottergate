package config

type DnsRecord struct {
	Type     string   `json:"type"`
	Address  string   `json:"address,omitempty"`  // A, AAAA
	Target   string   `json:"target,omitempty"`   // CNAME, NS, SRV, PTR
	Data     []string `json:"data,omitempty"`     // TXT
	Priority *int     `json:"priority,omitempty"` // MX, SRV
	Exchange string   `json:"exchange,omitempty"` // MX
	Weight   *int     `json:"weight,omitempty"`   // SRV
	Port     *int     `json:"port,omitempty"`     // SRV
}

type TlsConfig struct {
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	Ca         string `json:"ca,omitempty"`
	ServerName string `json:"serverName,omitempty"`
}

type HttpProxyConfig struct {
	Enabled             bool              `json:"enabled"`
	Upstream            string            `json:"upstream,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	ForwardRequestBody  bool              `json:"forwardRequestBody"`
	MaxRequestBodyBytes int64             `json:"maxRequestBodyBytes,omitempty"`
	ClientTls           *TlsConfig        `json:"clientTls,omitempty"`
}

type TlsProxyConfig struct {
	TargetPort int    `json:"targetPort,omitempty"`
	TargetIp   string `json:"targetIp,omitempty"`
}

type RedirectConfig struct {
	Enabled bool   `json:"enabled"`
	Code    int    `json:"code"`
	Target  string `json:"target"`
}

type HostConfig struct {
	Records   []DnsRecord      `json:"records,omitempty"`
	HttpProxy *HttpProxyConfig `json:"http_proxy,omitempty"`
	TlsProxy  *TlsProxyConfig  `json:"tls_proxy,omitempty"`
	Redirect  *RedirectConfig  `json:"redirect,omitempty"`
}

type FirewallConfig struct {
	DefaultPolicy    string   `json:"defaultPolicy"` // "allow" or "deny"
	AllowlistDomains []string `json:"allowlist_domains,omitempty"`
	BlocklistDomains []string `json:"blocklist_domains,omitempty"`
	AllowlistRanges  []string `json:"allowlist_ranges,omitempty"`
	BlocklistRanges  []string `json:"blocklist_ranges,omitempty"`
	AllowlistIps     []string `json:"allowlist_ips,omitempty"`
	BlocklistIps     []string `json:"blocklist_ips,omitempty"`
}

type ControlPlaneConfig struct {
	Enabled    *bool      `json:"enabled,omitempty"`
	Port       int        `json:"port,omitempty"`
	SocketPath string     `json:"socketPath,omitempty"`
	ApiKey     string     `json:"apiKey,omitempty"`
	Tls        *TlsConfig `json:"tls,omitempty"`
}

type ServerConfig struct {
	Port                 int                   `json:"port"`
	HttpPort             *int                  `json:"httpPort,omitempty"`
	HttpsPort            *int                  `json:"httpsPort,omitempty"`
	Tls                  *TlsConfig            `json:"tls,omitempty"`
	DotPort              *int                  `json:"dotPort,omitempty"`
	DohPort              *int                  `json:"dohPort,omitempty"`
	FallbackDns          string                `json:"fallbackDns,omitempty"`
	Firewall             *FirewallConfig       `json:"firewall,omitempty"`
	ControlPlane         *ControlPlaneConfig   `json:"controlPlane,omitempty"`
	DnsCacheMaxSize      int                   `json:"dnsCacheMaxSize,omitempty"`
	DnsCacheTtlMs        int                   `json:"dnsCacheTtlMs,omitempty"`
	MaxTcpConnections    int                   `json:"maxTcpConnections,omitempty"`
	TcpIdleTimeoutMs     int                   `json:"tcpIdleTimeoutMs,omitempty"`
	RateLimitMaxRequests int                   `json:"rateLimitMaxRequests,omitempty"`
	RateLimitWindowMs    int                   `json:"rateLimitWindowMs,omitempty"`
	UpstreamHttpProxy    string                `json:"upstreamHttpProxy,omitempty"`
	UpstreamHttpsProxy   string                `json:"upstreamHttpsProxy,omitempty"`
	UpstreamNoProxy      string                `json:"upstreamNoProxy,omitempty"`
	Hosts                map[string]HostConfig `json:"hosts"`
}

const (
	DnsClassIn = 1

	DnsTypeA       = 1
	DnsTypeNS      = 2
	DnsTypeCNAME   = 5
	DnsTypeSOA     = 6
	DnsTypePTR     = 12
	DnsTypeMX      = 15
	DnsTypeTXT     = 16
	DnsTypeAAAA    = 28
	DnsTypeSRV     = 33
	DnsTypeOPT     = 41
	DnsTypeDS      = 43
	DnsTypeRRSIG   = 46
	DnsTypeNSEC    = 47
	DnsTypeDNSKEY  = 48
	DnsTypeNSEC3   = 50

	DnsOpcodeQuery  = 0
	DnsOpcodeIquery = 1
	DnsOpcodeStatus = 2

	DnsRcodeNoError  = 0
	DnsRcodeFormErr  = 1
	DnsRcodeServFail = 2
	DnsRcodeNxDomain = 3
	DnsRcodeNotImp   = 4
	DnsRcodeRefused  = 5

	FlagQR = 1 << 15
	FlagAA = 1 << 10
	FlagTC = 1 << 9
	FlagRD = 1 << 8
	FlagRA = 1 << 7
	FlagAD = 1 << 5
	FlagCD = 1 << 4
)
