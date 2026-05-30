package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"ottergate/pkg/audit"
)

type DnsWireFormat struct {
	Buf    []byte
	Offset int
}

func NewDnsWireFormat(buffer []byte) *DnsWireFormat {
	if buffer == nil {
		buffer = make([]byte, 4096)
	}
	return &DnsWireFormat{
		Buf:    buffer,
		Offset: 0,
	}
}

func (dw *DnsWireFormat) WriteUint16(val uint16) {
	if dw.Offset+2 > len(dw.Buf) {
		dw.grow(2)
	}
	binary.BigEndian.PutUint16(dw.Buf[dw.Offset:], val)
	dw.Offset += 2
}

func (dw *DnsWireFormat) WriteUint8(val uint8) {
	if dw.Offset+1 > len(dw.Buf) {
		dw.grow(1)
	}
	dw.Buf[dw.Offset] = val
	dw.Offset += 1
}

func (dw *DnsWireFormat) WriteBytes(data []byte) {
	if dw.Offset+len(data) > len(dw.Buf) {
		dw.grow(len(data))
	}
	copy(dw.Buf[dw.Offset:], data)
	dw.Offset += len(data)
}

func (dw *DnsWireFormat) WriteUint32(val uint32) {
	if dw.Offset+4 > len(dw.Buf) {
		dw.grow(4)
	}
	binary.BigEndian.PutUint32(dw.Buf[dw.Offset:], val)
	dw.Offset += 4
}

func (dw *DnsWireFormat) WriteDomainName(name string) {
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		dw.WriteUint8(uint8(len(label)))
		dw.WriteBytes([]byte(label))
	}
	dw.WriteUint8(0)
}

func (dw *DnsWireFormat) grow(n int) {
	newLen := len(dw.Buf) * 2
	if newLen < dw.Offset+n {
		newLen = dw.Offset + n + 1024
	}
	newBuf := make([]byte, newLen)
	copy(newBuf, dw.Buf)
	dw.Buf = newBuf
}

func (dw *DnsWireFormat) ReadUint16() uint16 {
	if dw.Offset+2 > len(dw.Buf) {
		audit.Logger.Error("DnsWireFormat out of bounds read attempt: ReadUint16")
		dw.Offset = len(dw.Buf)
		return 0
	}
	val := binary.BigEndian.Uint16(dw.Buf[dw.Offset:])
	dw.Offset += 2
	return val
}

func (dw *DnsWireFormat) ReadUint8() uint8 {
	if dw.Offset+1 > len(dw.Buf) {
		audit.Logger.Error("DnsWireFormat out of bounds read attempt: ReadUint8")
		dw.Offset = len(dw.Buf)
		return 0
	}
	val := dw.Buf[dw.Offset]
	dw.Offset += 1
	return val
}

func (dw *DnsWireFormat) ReadUint32() uint32 {
	if dw.Offset+4 > len(dw.Buf) {
		audit.Logger.Error("DnsWireFormat out of bounds read attempt: ReadUint32")
		dw.Offset = len(dw.Buf)
		return 0
	}
	val := binary.BigEndian.Uint32(dw.Buf[dw.Offset:])
	dw.Offset += 4
	return val
}

func (dw *DnsWireFormat) ReadDomainName() string {
	var labels []string
	jumps := 0
	const maxJumps = 5
	currentOffset := dw.Offset
	savedOffset := -1

	for {
		if currentOffset >= len(dw.Buf) {
			audit.Logger.Error("DnsWireFormat out of bounds read attempt: ReadDomainName bounds exceeded")
			break
		}

		length := dw.Buf[currentOffset]
		currentOffset += 1

		if length == 0 {
			break
		}

		// Compression pointer check: 0xc0
		if (length & 0xc0) == 0xc0 {
			jumps++
			if jumps > maxJumps {
				audit.Logger.Error("DnsWireFormat pointer loop detected: ReadDomainName max jumps exceeded")
				break
			}
			if currentOffset >= len(dw.Buf) {
				audit.Logger.Error("DnsWireFormat out of bounds read attempt: ReadDomainName pointer read")
				break
			}

			ptr := int(length&0x3f)<<8 | int(dw.Buf[currentOffset])
			currentOffset += 1

			if savedOffset == -1 {
				savedOffset = currentOffset
			}
			currentOffset = ptr
			continue
		}

		if length > 63 || currentOffset+int(length) > len(dw.Buf) {
			audit.Logger.Error("DnsWireFormat malformed label length: ReadDomainName bounds exceeded")
			break
		}

		labelBytes := dw.Buf[currentOffset : currentOffset+int(length)]
		currentOffset += int(length)
		labels = append(labels, string(labelBytes))
	}

	if savedOffset != -1 {
		dw.Offset = savedOffset
	} else {
		dw.Offset = currentOffset
	}

	return strings.Join(labels, ".")
}

func (dw *DnsWireFormat) Finish() []byte {
	return dw.Buf[:dw.Offset]
}

func EncodeARecord(address string) []byte {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return []byte(ip4)
}

func EncodeAAAARecord(address string) []byte {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	return []byte(ip16)
}

func EncodeCNAME(target string) []byte {
	encoder := NewDnsWireFormat(nil)
	encoder.WriteDomainName(target)
	return encoder.Finish()
}

func EncodeTXT(data []string) []byte {
	encoder := NewDnsWireFormat(nil)
	for _, txt := range data {
		bytes := []byte(txt)
		encoder.WriteUint8(uint8(len(bytes)))
		encoder.WriteBytes(bytes)
	}
	return encoder.Finish()
}

func EncodeMX(priority uint16, exchange string) []byte {
	encoder := NewDnsWireFormat(nil)
	encoder.WriteUint16(priority)
	encoder.WriteDomainName(exchange)
	return encoder.Finish()
}

func EncodeNS(target string) []byte {
	encoder := NewDnsWireFormat(nil)
	encoder.WriteDomainName(target)
	return encoder.Finish()
}

func EncodeSRV(priority uint16, weight uint16, port uint16, target string) []byte {
	encoder := NewDnsWireFormat(nil)
	encoder.WriteUint16(priority)
	encoder.WriteUint16(weight)
	encoder.WriteUint16(port)
	encoder.WriteDomainName(target)
	return encoder.Finish()
}

func EncodePTR(target string) []byte {
	encoder := NewDnsWireFormat(nil)
	encoder.WriteDomainName(target)
	return encoder.Finish()
}

type ParsedQuestion struct {
	Name       string
	Type       uint16
	NextOffset int
}

func parseQuestion(query []byte, baseOffset int) (*ParsedQuestion, error) {
	decoder := NewDnsWireFormat(query)
	decoder.Offset = baseOffset

	name := decoder.ReadDomainName()
	if decoder.Offset > len(query)-4 {
		return nil, errors.New("out of bounds question parsing")
	}

	qtype := decoder.ReadUint16()
	qclass := decoder.ReadUint16()

	if qclass != 1 && qclass != 255 { // Class IN or ANY
		return nil, errors.New("unsupported DNS class")
	}

	return &ParsedQuestion{
		Name:       name,
		Type:       qtype,
		NextOffset: decoder.Offset,
	}, nil
}

func ExtractQuestions(query []byte) []ParsedQuestion {
	if len(query) < 12 {
		return nil
	}
	qdcount := binary.BigEndian.Uint16(query[4:6])
	var questions []ParsedQuestion
	offset := 12

	for i := 0; i < int(qdcount); i++ {
		q, err := parseQuestion(query, offset)
		if err != nil {
			break
		}
		questions = append(questions, *q)
		offset = q.NextOffset
	}

	return questions
}
