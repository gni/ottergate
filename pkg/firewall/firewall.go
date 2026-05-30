package firewall

import (
	"net"
	"strings"
	"ottergate/pkg/config"
)

type FirewallEngine struct{}

var Engine = &FirewallEngine{}

func (f *FirewallEngine) MatchCidr(ipStr, cidrStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

func (f *FirewallEngine) MatchDomain(domain, pattern string) bool {
	if pattern == "*" {
		return true
	}
	normDomain := strings.ToLower(strings.TrimSuffix(domain, "."))
	normPattern := strings.ToLower(strings.TrimSuffix(pattern, "."))

	if normPattern == normDomain {
		return true
	}

	if strings.HasPrefix(normPattern, "*.") {
		suffix := normPattern[2:]
		return strings.HasSuffix(normDomain, "."+suffix)
	}

	return false
}

func (f *FirewallEngine) NormalizeIp(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (f *FirewallEngine) IsRestrictedOutbound(ipStr string) bool {
	normalized := f.NormalizeIp(ipStr)
	ip := net.ParseIP(normalized)
	if ip == nil {
		return true // treat unparseable as restricted
	}

	// IPv4 Checks
	if ip4 := ip.To4(); ip4 != nil {
		b0 := ip4[0]
		b1 := ip4[1]

		if b0 == 0 {
			return true
		}
		if b0 == 10 {
			return true
		}
		if b0 == 127 {
			return true
		}
		if b0 == 100 && b1 >= 64 && b1 <= 127 {
			return true
		}
		if b0 == 169 && b1 == 254 {
			return true
		}
		if b0 == 172 && b1 >= 16 && b1 <= 31 {
			return true
		}
		if b0 == 192 && b1 == 168 {
			return true
		}
		if b0 >= 224 { // Multicast & Reserved (224.0.0.0 - 255.255.255.255)
			return true
		}
		return false
	}

	// IPv6 Checks
	if ip.To4() == nil && len(ip) == 16 {
		// Loopback & Unspecified check (::1 or ::)
		normalizedIPv6 := strings.ToLower(ip.String())
		if normalizedIPv6 == "::1" || normalizedIPv6 == "::" {
			return true
		}
		// fc00::/7 Unique Local Address (ULA) check: first 7 bits are 1111110 (0xfc or 0xfd)
		if (ip[0] & 0xfe) == 0xfc {
			return true
		}
		// fe80::/10 Link-Local address check: first 10 bits are 1111111010 (0xfe and top 2 bits of second byte are 10)
		if ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80 {
			return true
		}
	}

	return false
}

func (f *FirewallEngine) matchAllowlistIps(normalized string, fw *config.FirewallConfig) bool {
	if fw == nil {
		return false
	}
	for _, ip := range fw.AllowlistIps {
		if f.NormalizeIp(ip) == normalized {
			return true
		}
	}
	return false
}

func (f *FirewallEngine) matchAllowlistRanges(normalized string, fw *config.FirewallConfig) bool {
	if fw == nil {
		return false
	}
	for _, rangeStr := range fw.AllowlistRanges {
		if f.MatchCidr(normalized, rangeStr) {
			return true
		}
	}
	return false
}

func (f *FirewallEngine) EvaluateOutbound(ipStr string, fw *config.FirewallConfig) string {
	normalized := f.NormalizeIp(ipStr)

	if f.matchAllowlistIps(normalized, fw) || f.matchAllowlistRanges(normalized, fw) {
		return "ALLOW"
	}

	if f.IsRestrictedOutbound(normalized) {
		return "DENY"
	}

	return "ALLOW"
}

func (f *FirewallEngine) EvaluateIp(ipStr string, fw *config.FirewallConfig) string {
	if fw == nil {
		return "ALLOW"
	}

	normalized := f.NormalizeIp(ipStr)
	ip := net.ParseIP(normalized)
	if ip == nil {
		return "DENY"
	}

	// 1. Blocklist IP checks
	for _, bip := range fw.BlocklistIps {
		if f.NormalizeIp(bip) == normalized {
			return "DENY"
		}
	}

	// 2. Allowlist IP checks
	if f.matchAllowlistIps(normalized, fw) {
		return "ALLOW"
	}

	// 3. Blocklist CIDR checks
	for _, rangeStr := range fw.BlocklistRanges {
		if f.MatchCidr(normalized, rangeStr) {
			return "DENY"
		}
	}

	// 4. Allowlist CIDR checks
	if f.matchAllowlistRanges(normalized, fw) {
		return "ALLOW"
	}

	if fw.DefaultPolicy == "allow" {
		return "ALLOW"
	}
	return "DENY"
}

func (f *FirewallEngine) EvaluateDomain(domain string, fw *config.FirewallConfig) string {
	if fw == nil {
		return "ALLOW"
	}

	// Blocklist Domain checks
	for _, pattern := range fw.BlocklistDomains {
		if f.MatchDomain(domain, pattern) {
			return "DENY"
		}
	}

	// Allowlist Domain checks
	for _, pattern := range fw.AllowlistDomains {
		if f.MatchDomain(domain, pattern) {
			return "ALLOW"
		}
	}

	if fw.DefaultPolicy == "allow" {
		return "ALLOW"
	}
	return "DENY"
}
