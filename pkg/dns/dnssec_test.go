package dns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

func TestParseDnskey(t *testing.T) {
	// 1. Truncated check
	_, err := parseDnskey([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for truncated DNSKEY, got nil")
	}

	// 2. Valid layout check
	rdata := []byte{0x01, 0x00, 0x03, 0x0d, 0xaa, 0xbb, 0xcc}
	key, err := parseDnskey(rdata)
	if err != nil {
		t.Fatalf("unexpected error parsing valid DNSKEY: %v", err)
	}

	if key.Flags != 256 {
		t.Errorf("expected Flags 256, got %d", key.Flags)
	}
	if key.Protocol != 3 {
		t.Errorf("expected Protocol 3, got %d", key.Protocol)
	}
	if key.Algorithm != 13 {
		t.Errorf("expected Algorithm 13, got %d", key.Algorithm)
	}
	if len(key.PublicKey) != 3 || key.PublicKey[0] != 0xaa {
		t.Errorf("unexpected public key payload: %x", key.PublicKey)
	}
}

func TestParseRrsig(t *testing.T) {
	// 1. Truncated check
	_, err := parseRrsig([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for truncated RRSIG, got nil")
	}

	// 2. Valid layout check (type covered: A, algorithm: 13, labels: 2, original TTL: 3600)
	rdata := make([]byte, 18+11+10) // 18 byte prefix + canonical name label size + sig size
	binary.BigEndian.PutUint16(rdata[0:2], 1) // TypeCovered = A (1)
	rdata[2] = 13                             // Algorithm = ECDSA-P256-SHA256
	rdata[3] = 2                              // Labels = 2
	binary.BigEndian.PutUint32(rdata[4:8], 3600)
	binary.BigEndian.PutUint32(rdata[8:12], uint32(time.Now().Unix()+3600)) // Expiration
	binary.BigEndian.PutUint32(rdata[12:16], uint32(time.Now().Unix()-3600)) // Inception
	binary.BigEndian.PutUint16(rdata[16:18], 12345) // KeyTag

	// Append canonical name signer (test.local)
	signerBytes := encodeCanonicalName("test.local")
	copy(rdata[18:], signerBytes)

	// Append signature bytes
	copy(rdata[18+len(signerBytes):], []byte("signature-data"))

	sig, err := parseRrsig(rdata)
	if err != nil {
		t.Fatalf("unexpected error parsing valid RRSIG: %v", err)
	}

	if sig.TypeCovered != 1 {
		t.Errorf("expected TypeCovered 1, got %d", sig.TypeCovered)
	}
	if sig.KeyTag != 12345 {
		t.Errorf("expected KeyTag 12345, got %d", sig.KeyTag)
	}
	if sig.SignerName != "test.local" {
		t.Errorf("expected SignerName test.local, got %s", sig.SignerName)
	}
}

func TestCalculateKeyTag(t *testing.T) {
	rdata := []byte{0x01, 0x00, 0x03, 0x0d, 0xaa, 0xbb, 0xcc, 0xdd}
	key, err := parseDnskey(rdata)
	if err != nil {
		t.Fatalf("failed parsing key: %v", err)
	}

	// Calculate tag using the RFC 4034 checksum algorithm
	tag := calculateKeyTag(key, rdata)
	if tag == 0 {
		t.Error("calculated keytag is 0, expected checksum value")
	}
}

func TestVerifyDnssecResponseNoSignatures(t *testing.T) {
	// Mock an empty DNS response payload with standard headers (QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0)
	emptyResp := make([]byte, 12)
	ok := VerifyDnssecResponse(emptyResp, []string{"test.local"}, nil)
	if !ok {
		t.Error("VerifyDnssecResponse returned false for empty signatures response, expected true (unsigned domains fallback)")
	}
}

func TestVerifyDnssecResponseInvalidDnskey(t *testing.T) {
	// Construct a DNS packet header (ANCOUNT=2)
	buffer := make([]byte, 12+200)
	binary.BigEndian.PutUint16(buffer[4:6], 0) // QDCOUNT
	binary.BigEndian.PutUint16(buffer[6:8], 2) // ANCOUNT

	// Set query offset start
	offset := 12

	// Write record 1: RRSIG
	signerBytes := encodeCanonicalName("test.local")
	rrsigRdata := make([]byte, 18+len(signerBytes)+64)
	binary.BigEndian.PutUint16(rrsigRdata[0:2], 1) // Covers A
	rrsigRdata[2] = 13                             // ECDSA
	rrsigRdata[3] = 2
	binary.BigEndian.PutUint32(rrsigRdata[4:8], 3600)
	binary.BigEndian.PutUint32(rrsigRdata[8:12], uint32(time.Now().Unix()+3600))
	binary.BigEndian.PutUint32(rrsigRdata[12:16], uint32(time.Now().Unix()-3600))
	binary.BigEndian.PutUint16(rrsigRdata[16:18], 5555) // KeyTag
	copy(rrsigRdata[18:], signerBytes)

	// Write RRSIG Record to buffer
	dw1 := NewDnsWireFormat(buffer)
	dw1.Offset = offset
	dw1.WriteDomainName("test.local")
	dw1.WriteUint16(46)                         // Type RRSIG
	dw1.WriteUint16(1)                          // Class IN
	dw1.WriteUint32(3600)                       // TTL
	dw1.WriteUint16(uint16(len(rrsigRdata)))     // RdLength
	copy(buffer[dw1.Offset:], rrsigRdata)
	offset = dw1.Offset + len(rrsigRdata)

	// Write record 2: A Record (Type Covered)
	dw2 := NewDnsWireFormat(buffer)
	dw2.Offset = offset
	dw2.WriteDomainName("test.local")
	dw2.WriteUint16(1)  // Type A
	dw2.WriteUint16(1)  // Class IN
	dw2.WriteUint32(3600)
	dw2.WriteUint16(4)
	copy(buffer[dw2.Offset:], []byte{1, 2, 3, 4})
	offset = dw2.Offset + 4

	// Cut buffer to actual size used
	dnsPacket := buffer[:offset]

	// Verify validation fails closed because matching DNSKEY is missing
	ok := VerifyDnssecResponse(dnsPacket, []string{"test.local"}, nil)
	if ok {
		t.Error("VerifyDnssecResponse succeeded without matching DNSKEY record, expected fail-closed")
	}
}

func TestVerifySignatureECDSA(t *testing.T) {
	// 1. Generate local private ECDSA key on P-256 curve
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// 2. Build mock RRSIG header structure
	rrsig := &RRSIG{
		TypeCovered:         1,
		Algorithm:           13,
		Labels:              2,
		OriginalTTL:         3600,
		SignatureExpiration: uint32(time.Now().Unix() + 3600),
		SignatureInception:  uint32(time.Now().Unix() - 3600),
		KeyTag:              1234,
		SignerName:          "test.local",
	}

	// 3. Make mock covered RRSet (A record)
	rrset := []ParsedRecord{
		{
			Name:     "test.local",
			Type:     1,
			Class:    1,
			TTL:      3600,
			RdLength: 4,
			Rdata:    []byte{192, 168, 1, 1},
		},
	}

	// 4. Assemble signed data block canonically
	rrsigPrefix := make([]byte, 18)
	binary.BigEndian.PutUint16(rrsigPrefix[0:2], rrsig.TypeCovered)
	rrsigPrefix[2] = rrsig.Algorithm
	rrsigPrefix[3] = rrsig.Labels
	binary.BigEndian.PutUint32(rrsigPrefix[4:8], rrsig.OriginalTTL)
	binary.BigEndian.PutUint32(rrsigPrefix[8:12], rrsig.SignatureExpiration)
	binary.BigEndian.PutUint32(rrsigPrefix[12:16], rrsig.SignatureInception)
	binary.BigEndian.PutUint16(rrsigPrefix[16:18], rrsig.KeyTag)

	signerNameCanonical := encodeCanonicalName(rrsig.SignerName)

	var signedData []byte
	signedData = append(signedData, rrsigPrefix...)
	signedData = append(signedData, signerNameCanonical...)

	for _, rr := range rrset {
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

	// 5. Sign the payload using private ECDSA key
	h := sha256.New()
	h.Write(signedData)
	hashed := h.Sum(nil)

	rSig, sSig, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		t.Fatalf("signature creation failed: %v", err)
	}

	// Map signature coordinates to a 64-byte array format
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rSig.Bytes()):32], rSig.Bytes())
	copy(sigBytes[64-len(sSig.Bytes()):64], sSig.Bytes())

	rrsig.Signature = sigBytes
	rrsig.RawRdata = append(rrsigPrefix, signerNameCanonical...)

	// 6. Build DNSKEY from ECDSA public key structure
	pubX := privKey.PublicKey.X.Bytes()
	pubY := privKey.PublicKey.Y.Bytes()

	pubKeyBytes := make([]byte, 64)
	copy(pubKeyBytes[32-len(pubX):32], pubX)
	copy(pubKeyBytes[64-len(pubY):64], pubY)

	dnskey := &DNSKEY{
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: pubKeyBytes,
	}

	// 7. Verify signature logic passes
	valid := verifySignature(rrsig, rrset, dnskey)
	if !valid {
		t.Error("verifySignature returned false for valid ECDSA configuration, expected true")
	}

	// 8. Corrupt signature and verify it fails-closed
	rrsig.Signature[0] ^= 0xFF
	if verifySignature(rrsig, rrset, dnskey) {
		t.Error("verifySignature succeeded for corrupted signature, expected fail-closed")
	}
}
