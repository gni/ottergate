package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestWireDomainEncoding(t *testing.T) {
	name := "www.test.local"
	dw := NewDnsWireFormat(nil)
	dw.WriteDomainName(name)
	buf := dw.Finish()

	// Verify wire output matches standard length label byte format
	dwRead := NewDnsWireFormat(buf)
	decoded := dwRead.ReadDomainName()

	if decoded != name {
		t.Errorf("decoded domain mismatch: expected %q, got %q", name, decoded)
	}
}

func TestPointerLoopPrevention(t *testing.T) {
	// Create circular pointer: www.local.test -> pointer to start
	// We check that parser returns safely and does not loop infinitely.
	buf := make([]byte, 100)
	buf[0] = 3
	copy(buf[1:], "www")
	buf[4] = 0xc0 // compression pointer flag
	buf[5] = 0    // jumps back to offset 0 (itself!)

	dw := NewDnsWireFormat(buf)
	decoded := dw.ReadDomainName() // parser checks loop maxJumps limit and terminates safely!

	if decoded != "www.www.www.www.www.www" {
		t.Errorf("expected safely broken decompression parser loop result %q, got %q", "www.www.www.www.www.www", decoded)
	}
}

func Test0x20Encoding(t *testing.T) {
	query := make([]byte, 30)
	binary.BigEndian.PutUint16(query[0:2], 1234) // Transaction ID
	binary.BigEndian.PutUint16(query[4:6], 1)    // QDCOUNT = 1

	dw := NewDnsWireFormat(query)
	dw.Offset = 12
	dw.WriteDomainName("www.local.test")
	dw.WriteUint16(1) // TYPE A
	dw.WriteUint16(1) // CLASS IN
	rawQuery := dw.Finish()

	_, expectedNames := Apply0x20Encoding(rawQuery)

	if len(expectedNames) != 1 {
		t.Fatalf("expected 1 name parsed, got %d", len(expectedNames))
	}

	expectedName := expectedNames[0]

	// Verify case-insensitive match holds
	if strings.ToLower(expectedName) != "www.local.test" {
		t.Errorf("expected base name www.local.test, got %q", expectedName)
	}
}

func TestDnsRecordEncoders(t *testing.T) {
	// 1. EncodeARecord
	aBytes := EncodeARecord("192.168.1.1")
	if !bytes.Equal(aBytes, []byte{192, 168, 1, 1}) {
		t.Errorf("unexpected EncodeARecord result: %v", aBytes)
	}

	// 2. EncodeAAAARecord
	aaaaBytes := EncodeAAAARecord("2001:db8::1")
	parsedIp := net.ParseIP("2001:db8::1")
	if !bytes.Equal(aaaaBytes, []byte(parsedIp.To16())) {
		t.Errorf("unexpected EncodeAAAARecord result: %v", aaaaBytes)
	}

	// 3. EncodeCNAME
	cnameBytes := EncodeCNAME("alias.local")
	dwCname := NewDnsWireFormat(cnameBytes)
	if name := dwCname.ReadDomainName(); name != "alias.local" {
		t.Errorf("unexpected EncodeCNAME target decoded: %q", name)
	}

	// 4. EncodeTXT
	txtBytes := EncodeTXT([]string{"txt-val-1", "txt-val-2"})
	dwTxt := NewDnsWireFormat(txtBytes)
	len1 := dwTxt.ReadUint8()
	val1 := string(dwTxt.Buf[dwTxt.Offset : dwTxt.Offset+int(len1)])
	dwTxt.Offset += int(len1)
	len2 := dwTxt.ReadUint8()
	val2 := string(dwTxt.Buf[dwTxt.Offset : dwTxt.Offset+int(len2)])
	dwTxt.Offset += int(len2)

	if val1 != "txt-val-1" || val2 != "txt-val-2" {
		t.Errorf("unexpected EncodeTXT decoded values: %q, %q", val1, val2)
	}

	// 5. EncodeMX
	mxBytes := EncodeMX(10, "mail.test.local")
	dwMx := NewDnsWireFormat(mxBytes)
	priority := dwMx.ReadUint16()
	exchange := dwMx.ReadDomainName()

	if priority != 10 || exchange != "mail.test.local" {
		t.Errorf("unexpected EncodeMX values: priority=%d, exchange=%q", priority, exchange)
	}

	// 6. EncodeNS
	nsBytes := EncodeNS("ns.test.local")
	dwNs := NewDnsWireFormat(nsBytes)
	if name := dwNs.ReadDomainName(); name != "ns.test.local" {
		t.Errorf("unexpected EncodeNS target decoded: %q", name)
	}

	// 7. EncodeSRV
	srvBytes := EncodeSRV(5, 10, 5060, "sip.test.local")
	dwSrv := NewDnsWireFormat(srvBytes)
	pri := dwSrv.ReadUint16()
	weight := dwSrv.ReadUint16()
	port := dwSrv.ReadUint16()
	target := dwSrv.ReadDomainName()

	if pri != 5 || weight != 10 || port != 5060 || target != "sip.test.local" {
		t.Errorf("unexpected EncodeSRV values: pri=%d, weight=%d, port=%d, target=%q", pri, weight, port, target)
	}

	// 8. EncodePTR
	ptrBytes := EncodePTR("ptr.test.local")
	dwPtr := NewDnsWireFormat(ptrBytes)
	if name := dwPtr.ReadDomainName(); name != "ptr.test.local" {
		t.Errorf("unexpected EncodePTR target decoded: %q", name)
	}
}
