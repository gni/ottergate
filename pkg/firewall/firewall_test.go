package firewall

import (
	"testing"
	"ottergate/pkg/config"
)

func TestMatchCidr(t *testing.T) {
	if !Engine.MatchCidr("192.168.1.15", "192.168.1.0/24") {
		t.Error("expected 192.168.1.15 to match 192.168.1.0/24")
	}
	if Engine.MatchCidr("10.0.0.1", "192.168.1.0/24") {
		t.Error("did not expect 10.0.0.1 to match 192.168.1.0/24")
	}
}

func TestMatchDomain(t *testing.T) {
	if !Engine.MatchDomain("sub.example.com", "*.example.com") {
		t.Error("expected sub.example.com to match *.example.com")
	}
	if !Engine.MatchDomain("sub.sub.example.com", "*.example.com") {
		t.Error("expected sub.sub.example.com to match *.example.com")
	}
	if Engine.MatchDomain("example.com.org", "*.example.com") {
		t.Error("did not expect example.com.org to match *.example.com")
	}
}

func TestIsRestrictedOutbound(t *testing.T) {
	restricted := []string{
		"127.0.0.1",
		"10.0.0.5",
		"192.168.1.100",
		"172.16.50.2",
		"169.254.169.254",
		"::1",
		"fe80::1",
		"fc00::9",
	}

	for _, ip := range restricted {
		if !Engine.IsRestrictedOutbound(ip) {
			t.Errorf("expected IP %s to be restricted as outbound target (SSRF prevention)", ip)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"142.250.190.46",
	}

	for _, ip := range allowed {
		if Engine.IsRestrictedOutbound(ip) {
			t.Errorf("expected public IP %s to NOT be restricted outbound target", ip)
		}
	}
}

func TestEvaluateIp(t *testing.T) {
	fw := &config.FirewallConfig{
		DefaultPolicy:    "deny",
		AllowlistIps:     []string{"192.168.1.50"},
		BlocklistIps:     []string{"8.8.8.8"},
		BlocklistRanges:  []string{"192.168.2.0/24"},
	}

	if Engine.EvaluateIp("8.8.8.8", fw) != "DENY" {
		t.Error("expected blocklisted IP 8.8.8.8 to be denied")
	}
	if Engine.EvaluateIp("192.168.2.15", fw) != "DENY" {
		t.Error("expected IP in blocklisted CIDR to be denied")
	}
	if Engine.EvaluateIp("192.168.1.50", fw) != "ALLOW" {
		t.Error("expected allowlisted IP to be allowed")
	}
	if Engine.EvaluateIp("8.8.4.4", fw) != "DENY" {
		t.Error("expected default policy 'deny' to apply to unlisted IP")
	}
}
