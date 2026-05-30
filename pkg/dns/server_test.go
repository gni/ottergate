package dns

import (
	"testing"
	"ottergate/pkg/config"
)

func TestDnsServerHostMatching(t *testing.T) {
	cfg := &config.ServerConfig{
		Port: 53,
		Hosts: map[string]config.HostConfig{
			"exact.local": {
				Records: []config.DnsRecord{
					{Type: "A", Address: "10.0.0.1"},
				},
			},
			"*.wildcard.local": {
				Records: []config.DnsRecord{
					{Type: "A", Address: "10.0.0.2"},
				},
			},
			"*": {
				Records: []config.DnsRecord{
					{Type: "A", Address: "10.0.0.3"},
				},
			},
		},
	}

	server := NewDevDnsServer(cfg)

	// 1. Test IsLocalHost helper
	if !server.IsLocalHost("exact.local.") {
		t.Error("expected exact.local to be registered as local host")
	}
	if server.IsLocalHost("unknown.local") {
		t.Error("expected unknown.local not to be registered as local host")
	}

	// 2. Test findHostConfig exact match
	c1, ok1 := server.findHostConfig("exact.local")
	if !ok1 || len(c1.Records) != 1 || c1.Records[0].Address != "10.0.0.1" {
		t.Error("failed matching exact domain config")
	}

	// 3. Test findHostConfig wildcard match
	c2, ok2 := server.findHostConfig("sub.wildcard.local")
	if !ok2 || len(c2.Records) != 1 || c2.Records[0].Address != "10.0.0.2" {
		t.Error("failed matching wildcard domain config")
	}

	// 4. Test findHostConfig root wildcard fallback
	c3, ok3 := server.findHostConfig("fallback.other.local")
	if !ok3 || len(c3.Records) != 1 || c3.Records[0].Address != "10.0.0.3" {
		t.Error("failed falling back to root wildcard config")
	}
}
