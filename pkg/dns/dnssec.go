package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
	"ottergate/pkg/audit"
)

type ParsedRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RdLength uint16
	Rdata    []byte
	Offset   int
}

type RRSIG struct {
	TypeCovered         uint16
	Algorithm           uint8
	Labels              uint8
	OriginalTTL         uint32
	SignatureExpiration uint32
	SignatureInception  uint32
	KeyTag              uint16
	SignerName          string
	Signature           []byte
	RawRdata            []byte
}

type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

type DnssecValidator struct{}

func parseDomainNameCanonical(buf []byte, offset int) (string, int) {
	dw := NewDnsWireFormat(buf)
	dw.Offset = offset
	name := dw.ReadDomainName()
	return strings.ToLower(name), dw.Offset
}

func encodeCanonicalName(name string) []byte {
	dw := NewDnsWireFormat(nil)
	dw.WriteDomainName(strings.ToLower(name))
	return dw.Finish()
}

func parseDnskey(rdata []byte) (*DNSKEY, error) {
	if len(rdata) < 4 {
		return nil, errors.New("DNSKEY rdata too short")
	}
	flags := binary.BigEndian.Uint16(rdata[0:2])
	protocol := rdata[2]
	algorithm := rdata[3]
	pubKey := rdata[4:]
	return &DNSKEY{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: pubKey,
	}, nil
}

func parseRrsig(rdata []byte) (*RRSIG, error) {
	if len(rdata) < 18 {
		return nil, errors.New("RRSIG rdata too short")
	}
	typeCovered := binary.BigEndian.Uint16(rdata[0:2])
	algorithm := rdata[2]
	labels := rdata[3]
	originalTTL := binary.BigEndian.Uint32(rdata[4:8])
	expiration := binary.BigEndian.Uint32(rdata[8:12])
	inception := binary.BigEndian.Uint32(rdata[12:16])
	keyTag := binary.BigEndian.Uint16(rdata[16:18])

	dw := NewDnsWireFormat(rdata)
	dw.Offset = 18
	signerName := dw.ReadDomainName()
	signature := rdata[dw.Offset:]

	return &RRSIG{
		TypeCovered:         typeCovered,
		Algorithm:           algorithm,
		Labels:              labels,
		OriginalTTL:         originalTTL,
		SignatureExpiration: expiration,
		SignatureInception:  inception,
		KeyTag:              keyTag,
		SignerName:          signerName,
		Signature:           signature,
		RawRdata:            rdata,
	}, nil
}

func extractRecords(buffer []byte) (qdcount int, answers, authorities, additionals []ParsedRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic during record extraction")
		}
	}()

	if len(buffer) < 12 {
		return 0, nil, nil, nil, errors.New("DNS packet too short")
	}

	dw := NewDnsWireFormat(buffer)
	dw.Offset = 4
	qdcount = int(dw.ReadUint16())
	ancount := int(dw.ReadUint16())
	nscount := int(dw.ReadUint16())
	arcount := int(dw.ReadUint16())

	// Skip question section
	for i := 0; i < qdcount; i++ {
		dw.ReadDomainName()
		dw.Offset += 4 // type and class
	}

	parseSection := func(count int) []ParsedRecord {
		var records []ParsedRecord
		for i := 0; i < count; i++ {
			if dw.Offset >= len(buffer) {
				break
			}
			name := strings.ToLower(dw.ReadDomainName())
			rtype := dw.ReadUint16()
			rclass := dw.ReadUint16()
			ttl := dw.ReadUint32()
			rdlen := dw.ReadUint16()

			if dw.Offset+int(rdlen) > len(buffer) {
				break
			}

			rdata := buffer[dw.Offset : dw.Offset+int(rdlen)]
			recordOffset := dw.Offset
			dw.Offset += int(rdlen)

			records = append(records, ParsedRecord{
				Name:     name,
				Type:     rtype,
				Class:    rclass,
				TTL:      ttl,
				RdLength: rdlen,
				Rdata:    rdata,
				Offset:   recordOffset,
			})
		}
		return records
	}

	answers = parseSection(ancount)
	authorities = parseSection(nscount)
	additionals = parseSection(arcount)

	return qdcount, answers, authorities, additionals, nil
}

func verifySignature(rrsig *RRSIG, rrset []ParsedRecord, dnskey *DNSKEY) bool {
	now := uint32(time.Now().Unix())
	if now > rrsig.SignatureExpiration || now < rrsig.SignatureInception {
		audit.Logger.Error("DNSSEC Temporal Fault: RRSIG outside validity window")
		return false
	}

	rrsigPrefix := rrsig.RawRdata[0:18]
	signerNameCanonical := encodeCanonicalName(rrsig.SignerName)

	var signedData []byte
	signedData = append(signedData, rrsigPrefix...)
	signedData = append(signedData, signerNameCanonical...)

	// Canonical RRSet Sorting: sort by RDATA lexicographically
	sortedRrset := make([]ParsedRecord, len(rrset))
	copy(sortedRrset, rrset)
	sort.Slice(sortedRrset, func(i, j int) bool {
		a := sortedRrset[i].Rdata
		b := sortedRrset[j].Rdata
		minLen := len(a)
		if len(b) < minLen {
			minLen = len(b)
		}
		for k := 0; k < minLen; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})

	for _, rr := range sortedRrset {
		ownerCanonical := encodeCanonicalName(rr.Name)
		header := make([]byte, 10)
		binary.BigEndian.PutUint16(header[0:2], rr.Type)
		binary.BigEndian.PutUint16(header[2:4], rr.Class)
		binary.BigEndian.PutUint32(header[4:8], rrsig.OriginalTTL)
		binary.BigEndian.PutUint16(header[8:10], rr.RdLength)

		signedData = append(signedData, ownerCanonical...)
		signedData = append(signedData, header...)
		signedData = append(signedData, rr.Rdata...)
	}

	hasher := sha256.New()
	hasher.Write(signedData)
	hashed := hasher.Sum(nil)

	if rrsig.Algorithm == 8 { // RSA-SHA256
		pubKeyRaw := dnskey.PublicKey
		if len(pubKeyRaw) < 2 {
			return false
		}
		exponentLen := int(pubKeyRaw[0])
		offset := 1
		if exponentLen == 0 {
			if len(pubKeyRaw) < 3 {
				return false
			}
			exponentLen = int(binary.BigEndian.Uint16(pubKeyRaw[1:3]))
			offset = 3
		}
		if len(pubKeyRaw) < offset+exponentLen {
			return false
		}
		exponentBytes := pubKeyRaw[offset : offset+exponentLen]
		modulusBytes := pubKeyRaw[offset+exponentLen:]

		var exp int
		for _, b := range exponentBytes {
			exp = (exp << 8) | int(b)
		}

		n := new(big.Int).SetBytes(modulusBytes)
		pubKey := &rsa.PublicKey{
			N: n,
			E: exp,
		}

		err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, rrsig.Signature)
		return err == nil

	} else if rrsig.Algorithm == 13 { // ECDSA-P256-SHA256
		pubKeyRaw := dnskey.PublicKey
		if len(pubKeyRaw) != 64 {
			return false
		}
		x := new(big.Int).SetBytes(pubKeyRaw[0:32])
		y := new(big.Int).SetBytes(pubKeyRaw[32:64])
		pubKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

		if len(rrsig.Signature) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(rrsig.Signature[0:32])
		s := new(big.Int).SetBytes(rrsig.Signature[32:64])

		return ecdsa.Verify(pubKey, hashed, r, s)
	}

	audit.Logger.System(fmt.Sprintf("DNSSEC Skipped: Unsupported cryptographic algorithm %d", rrsig.Algorithm))
	return false
}

func calculateKeyTag(k *DNSKEY, rawRdata []byte) uint16 {
	if k.Algorithm == 1 { // RSAMD5 tag calculation (unsupported, but preserved structure)
		if len(k.PublicKey) < 3 {
			return 0
		}
		return uint16(k.PublicKey[len(k.PublicKey)-3])<<8 + uint16(k.PublicKey[len(k.PublicKey)-2])
	}

	var ac uint32
	for i := 0; i < len(rawRdata); i++ {
		if (i & 1) != 0 {
			ac += uint32(rawRdata[i])
		} else {
			ac += uint32(rawRdata[i]) << 8
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff)
}

func VerifyDnssecResponse(buffer []byte) bool {
	_, answers, authorities, additionals, err := extractRecords(buffer)
	if err != nil {
		return false
	}

	var allRecords []ParsedRecord
	allRecords = append(allRecords, answers...)
	allRecords = append(allRecords, authorities...)
	allRecords = append(allRecords, additionals...)

	var dnskeyRecords []ParsedRecord
	var rrsigRecords []ParsedRecord

	for _, r := range allRecords {
		if r.Type == 48 { // DNSKEY
			dnskeyRecords = append(dnskeyRecords, r)
		} else if r.Type == 46 { // RRSIG
			rrsigRecords = append(rrsigRecords, r)
		}
	}

	if len(rrsigRecords) == 0 {
		return true // No signature, allowed if unsigned domain (fallback)
	}

	for _, sigRec := range rrsigRecords {
		rrsig, err := parseRrsig(sigRec.Rdata)
		if err != nil {
			continue
		}

		// Filter RRSet covered by this RRSIG
		var coveredRrset []ParsedRecord
		for _, rr := range answers {
			if rr.Name == sigRec.Name && rr.Type == rrsig.TypeCovered {
				coveredRrset = append(coveredRrset, rr)
			}
		}
		if len(coveredRrset) == 0 {
			continue
		}

		// Find matching DNSKEY
		var matchingDnskey *DNSKEY
		for _, kRec := range dnskeyRecords {
			k, err := parseDnskey(kRec.Rdata)
			if err != nil {
				continue
			}
			tag := calculateKeyTag(k, kRec.Rdata)
			if tag == rrsig.KeyTag {
				matchingDnskey = k
				break
			}
		}

		if matchingDnskey == nil {
			audit.Logger.Error(fmt.Sprintf("DNSSEC Cryptographic Fault: No matching DNSKEY found for RRSIG key tag %d", rrsig.KeyTag))
			return false
		}

		if !verifySignature(rrsig, coveredRrset, matchingDnskey) {
			audit.Logger.Error(fmt.Sprintf("DNSSEC Cryptographic Fault: Signature validation failed for %s", sigRec.Name))
			return false
		}
	}

	return true
}
