package dns

import (
	"encoding/binary"
	"testing"
	"ottergate/pkg/config"
)

func BenchmarkCacheGet(b *testing.B) {
	c := NewDnsCache(1000, 300000)
	questions := []ParsedQuestion{
		{Name: "benchmark.test.local", Type: 1},
	}
	key := c.GenerateCacheKey(questions)
	response := make([]byte, 12)
	c.Put(key, response)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, ok := c.Get(key)
		if !ok {
			b.Fatal("cache lookup failed")
		}
	}
}

func BenchmarkLocalResolve(b *testing.B) {
	cfg := &config.ServerConfig{
		Port: 53,
		Hosts: map[string]config.HostConfig{
			"benchmark.test.local": {
				Records: []config.DnsRecord{
					{Type: "A", Address: "10.0.0.1"},
				},
			},
		},
	}
	server := NewDevDnsServer(cfg)

	// Build a valid query packet
	query := make([]byte, 36)
	binary.BigEndian.PutUint16(query[0:2], 1234)
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // RD = 1
	binary.BigEndian.PutUint16(query[4:6], 1)      // QDCOUNT = 1
	dw := NewDnsWireFormat(query)
	dw.Offset = 12
	dw.WriteDomainName("benchmark.test.local")
	dw.WriteUint16(1) // Type A
	dw.WriteUint16(1) // Class IN
	packet := dw.Finish()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := server.Resolve(packet, "127.0.0.1")
		if res == nil {
			b.Fatal("local resolve failed")
		}
	}
}

func BenchmarkQueryParsing(b *testing.B) {
	// Build a valid query packet
	query := make([]byte, 36)
	binary.BigEndian.PutUint16(query[0:2], 1234)
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // RD = 1
	binary.BigEndian.PutUint16(query[4:6], 1)      // QDCOUNT = 1
	dw := NewDnsWireFormat(query)
	dw.Offset = 12
	dw.WriteDomainName("benchmark.test.local")
	dw.WriteUint16(1) // Type A
	dw.WriteUint16(1) // Class IN
	packet := dw.Finish()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		questions := ExtractQuestions(packet)
		if len(questions) == 0 {
			b.Fatal("parsing failed")
		}
	}
}
