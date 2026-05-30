package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"ottergate/pkg/audit"
	"ottergate/pkg/config"
	"ottergate/pkg/firewall"
)

type DevDnsServer struct {
	mu           sync.RWMutex
	cfg          *config.ServerConfig
	cache        *DnsCache
	dnsCacheTtl  int
	dnsCacheSize int
}

func NewDevDnsServer(cfg *config.ServerConfig) *DevDnsServer {
	return &DevDnsServer{
		cfg:          cfg,
		cache:        NewDnsCache(cfg.DnsCacheMaxSize, cfg.DnsCacheTtlMs),
		dnsCacheTtl:  cfg.DnsCacheTtlMs,
		dnsCacheSize: cfg.DnsCacheMaxSize,
	}
}

func (s *DevDnsServer) UpdateConfig(newCfg *config.ServerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = newCfg
	s.cache = NewDnsCache(newCfg.DnsCacheMaxSize, newCfg.DnsCacheTtlMs)
	s.dnsCacheTtl = newCfg.DnsCacheTtlMs
	s.dnsCacheSize = newCfg.DnsCacheMaxSize
}

func (s *DevDnsServer) normalizeHost(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (s *DevDnsServer) IsLocalHost(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil || s.cfg.Hosts == nil {
		return false
	}
	normalized := s.normalizeHost(name)
	if normalized == "*" || normalized == "" {
		return false
	}
	_, ok := s.cfg.Hosts[normalized]
	return ok
}

func (s *DevDnsServer) findHostConfig(normalizedName string) (config.HostConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact match check (avoiding wildcards)
	if !strings.Contains(normalizedName, "*") {
		if val, ok := s.cfg.Hosts[normalizedName]; ok {
			return val, true
		}
	}

	// Wildcard suffix matches (e.g. *.example.com)
	labels := strings.Split(normalizedName, ".")
	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		wildcardKey := "*." + suffix
		if val, ok := s.cfg.Hosts[wildcardKey]; ok {
			return val, true
		}
	}

	// Wildcard root match
	if val, ok := s.cfg.Hosts["*"]; ok {
		return val, true
	}

	return config.HostConfig{}, false
}

func (s *DevDnsServer) toTypeNumber(recordType string) uint16 {
	switch strings.ToUpper(recordType) {
	case "A":
		return config.DnsTypeA
	case "AAAA":
		return config.DnsTypeAAAA
	case "CNAME":
		return config.DnsTypeCNAME
	case "TXT":
		return config.DnsTypeTXT
	case "MX":
		return config.DnsTypeMX
	case "NS":
		return config.DnsTypeNS
	case "SRV":
		return config.DnsTypeSRV
	case "PTR":
		return config.DnsTypePTR
	default:
		return 0
	}
}

func (s *DevDnsServer) toTypeString(t uint16) string {
	switch t {
	case config.DnsTypeA:
		return "A"
	case config.DnsTypeAAAA:
		return "AAAA"
	case config.DnsTypeCNAME:
		return "CNAME"
	case config.DnsTypeTXT:
		return "TXT"
	case config.DnsTypeMX:
		return "MX"
	case config.DnsTypeNS:
		return "NS"
	case config.DnsTypeSRV:
		return "SRV"
	case config.DnsTypePTR:
		return "PTR"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func (s *DevDnsServer) buildSingleAnswer(r config.DnsRecord) []byte {
	var rdata []byte

	switch r.Type {
	case "A":
		rdata = EncodeARecord(r.Address)
	case "AAAA":
		rdata = EncodeAAAARecord(r.Address)
	case "CNAME":
		rdata = EncodeCNAME(r.Target)
	case "TXT":
		rdata = EncodeTXT(r.Data)
	case "MX":
		pri := uint16(0)
		if r.Priority != nil {
			pri = uint16(*r.Priority)
		}
		rdata = EncodeMX(pri, r.Exchange)
	case "NS":
		rdata = EncodeNS(r.Target)
	case "SRV":
		pri := uint16(0)
		if r.Priority != nil {
			pri = uint16(*r.Priority)
		}
		w := uint16(0)
		if r.Weight != nil {
			w = uint16(*r.Weight)
		}
		p := uint16(0)
		if r.Port != nil {
			p = uint16(*r.Port)
		}
		rdata = EncodeSRV(pri, w, p, r.Target)
	case "PTR":
		rdata = EncodePTR(r.Target)
	}

	entry := make([]byte, 10+len(rdata))
	binary.BigEndian.PutUint16(entry[0:2], s.toTypeNumber(r.Type))
	binary.BigEndian.PutUint16(entry[2:4], config.DnsClassIn)
	binary.BigEndian.PutUint32(entry[4:8], 300) // Default TTL 300 seconds
	binary.BigEndian.PutUint16(entry[8:10], uint16(len(rdata)))
	copy(entry[10:], rdata)

	return entry
}

func (s *DevDnsServer) buildAnswers(hostConfig config.HostConfig, recordType uint16) [][]byte {
	var answers [][]byte
	for _, r := range hostConfig.Records {
		if s.toTypeNumber(r.Type) == recordType {
			answers = append(answers, s.buildSingleAnswer(r))
		}
	}
	return answers
}

func (s *DevDnsServer) GenerateErrorResponse(query []byte, rcode int) []byte {
	if len(query) < 12 {
		return nil
	}
	id := binary.BigEndian.Uint16(query[0:2])
	flags := binary.BigEndian.Uint16(query[2:4])
	questions := ExtractQuestions(query)

	return BuildResponsePacket(id, flags, rcode, questions, nil)
}

func BuildResponsePacket(id uint16, flags uint16, rcode int, questions []ParsedQuestion, answerBuffers [][]byte) []byte {
	encoder := NewDnsWireFormat(nil)

	combinedFlags := (flags &^ 0x8000) | config.FlagQR | config.FlagAA | uint16(rcode)

	encoder.WriteUint16(id)
	encoder.WriteUint16(combinedFlags)
	encoder.WriteUint16(uint16(len(questions)))

	answerCountOffset := encoder.Offset
	encoder.WriteUint16(0) // placeholder for ancount
	encoder.WriteUint16(0) // nscount
	encoder.WriteUint16(0) // arcount

	for _, q := range questions {
		encoder.WriteDomainName(q.Name)
		encoder.WriteUint16(q.Type)
		encoder.WriteUint16(config.DnsClassIn)
	}

	var ancount uint16
	for _, ans := range answerBuffers {
		if len(ans) < 10 {
			continue
		}
		encoder.WriteUint8(0xc0)
		encoder.WriteUint8(0x0c) // compression pointer to original question
		encoder.WriteBytes(ans)
		ancount++
	}

	binary.BigEndian.PutUint16(encoder.Buf[answerCountOffset:], ancount)
	return encoder.Finish()
}

func BuildNoErrorResponse(id uint16, flags uint16, questions []ParsedQuestion) []byte {
	return BuildResponsePacket(id, flags, config.DnsRcodeNoError, questions, nil)
}

func (s *DevDnsServer) Resolve(query []byte, sourceIp string) []byte {
	if len(query) < 12 {
		return nil
	}

	flags := binary.BigEndian.Uint16(query[2:4])

	// Check QR flag (must be 0 for query)
	if (flags & 0x8000) != 0 {
		return nil
	}

	// Check RD flag (must be 1 for recursion desired)
	if (flags & 0x0100) == 0 {
		return nil
	}

	qdcount := binary.BigEndian.Uint16(query[4:6])
	ancount := binary.BigEndian.Uint16(query[6:8])
	nscount := binary.BigEndian.Uint16(query[8:10])

	if qdcount == 0 || ancount > 0 || nscount > 0 {
		return nil
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
		}{Name: q.Name, Type: s.toTypeString(q.Type)})
	}

	// Cache Check
	cacheKey := s.cache.GenerateCacheKey(questions)
	if cachedBytes, _, ok := s.cache.Get(cacheKey); ok {
		cachedRcode := int(binary.BigEndian.Uint16(cachedBytes[2:4]) & 0xf)
		isLocal := len(logQuestions) > 0 && s.IsLocalHost(logQuestions[0].Name)
		audit.Logger.DNS(sourceIp, logQuestions, cachedRcode, true, ParseResolvedIpv4s(cachedBytes), isLocal)

		// Create a copy of the cached bytes and rewrite the transaction ID to match the current query
		responseCopy := make([]byte, len(cachedBytes))
		copy(responseCopy, cachedBytes)
		if len(query) >= 2 {
			responseCopy[0] = query[0]
			responseCopy[1] = query[1]
		}
		return responseCopy
	}

	if len(questions) == 0 {
		return s.GenerateErrorResponse(query, config.DnsRcodeNxDomain)
	}

	var answers [][]byte
	hasAnyMatch := false
	allQuestionsUnknown := true

	for _, q := range questions {
		normalizedName := s.normalizeHost(q.Name)
		hostConfig, ok := s.findHostConfig(normalizedName)
		if !ok {
			continue
		}

		allQuestionsUnknown = false
		recordAnswers := s.buildAnswers(hostConfig, q.Type)
		if len(recordAnswers) > 0 {
			answers = append(answers, recordAnswers...)
			hasAnyMatch = true
		}
	}

	s.mu.RLock()
	fw := s.cfg.Firewall
	fallbackDns := s.cfg.FallbackDns
	s.mu.RUnlock()

	// If no match found and all questions are unknown, evaluate firewall rules and fallback
	if !hasAnyMatch && allQuestionsUnknown {
		allowed := true
		for _, q := range questions {
			if firewall.Engine.EvaluateDomain(q.Name, fw) == "DENY" {
				allowed = false
				break
			}
		}

		if !allowed {
			var names []string
			for _, q := range questions {
				names = append(names, q.Name)
			}
			audit.Logger.Firewall(sourceIp, strings.Join(names, ", "), "DENY", "Domain Blocked")
			return s.GenerateErrorResponse(query, config.DnsRcodeRefused)
		}

		if fallbackDns == "" {
			resp := s.GenerateErrorResponse(query, config.DnsRcodeNxDomain)
			s.cache.Put(cacheKey, resp)
			isLocal := len(logQuestions) > 0 && s.IsLocalHost(logQuestions[0].Name)
			audit.Logger.DNS(sourceIp, logQuestions, config.DnsRcodeNxDomain, false, nil, isLocal)
			return resp
		}

		return nil // Trigger forwarder fallback
	}

	id := binary.BigEndian.Uint16(query[0:2])

	if len(answers) > 0 {
		resp := BuildResponsePacket(id, flags, config.DnsRcodeNoError, questions, answers)
		s.cache.Put(cacheKey, resp)
		isLocal := len(logQuestions) > 0 && s.IsLocalHost(logQuestions[0].Name)
		audit.Logger.DNS(sourceIp, logQuestions, config.DnsRcodeNoError, false, ParseResolvedIpv4s(resp), isLocal)
		return resp
	}

	if !allQuestionsUnknown {
		resp := BuildNoErrorResponse(id, flags, questions)
		s.cache.Put(cacheKey, resp)
		isLocal := len(logQuestions) > 0 && s.IsLocalHost(logQuestions[0].Name)
		audit.Logger.DNS(sourceIp, logQuestions, config.DnsRcodeNoError, false, nil, isLocal)
		return resp
	}

	return nil
}

func (s *DevDnsServer) HasRecord(name string, qtype uint16) bool {
	normalizedName := s.normalizeHost(name)
	hostConfig, ok := s.findHostConfig(normalizedName)
	if !ok {
		return false
	}

	for _, r := range hostConfig.Records {
		if s.toTypeNumber(r.Type) == qtype {
			return true
		}
	}
	return false
}
