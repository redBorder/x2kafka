package flow

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

func TestNetFlowV5Parsing(t *testing.T) {
	// Build a valid NetFlow v5 packet: 24-byte header + 1 record (48 bytes)
	buf := new(bytes.Buffer)

	// Header:
	// Version: 5 (uint16)
	// Count: 1 (uint16)
	// SysUptime: 10000 ms (uint32)
	// UnixSecs: 1700000000 (uint32)
	// UnixNanoSecs: 0 (uint32)
	// FlowSequence: 42 (uint32)
	// EngineType: 0 (uint8), EngineID: 0 (uint8)
	// SamplingInterval: 0 (uint16)
	_ = binary.Write(buf, binary.BigEndian, uint16(5))
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint32(10000))
	_ = binary.Write(buf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(42))
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// Record 1 (48 bytes):
	// srcIP: 192.168.1.50 (4 bytes)
	// dstIP: 10.0.0.1 (4 bytes)
	// nextHop: 0.0.0.0 (4 bytes)
	// inputIf: 1 (uint16), outputIf: 2 (uint16)
	// dPkts: 15 (uint32), dOctets: 1500 (uint32)
	// first: 2000 (uint32), last: 8000 (uint32)
	// srcPort: 44332 (uint16), dstPort: 80 (uint16)
	// pad1: 0 (uint8), tcpFlags: 0x12 (SYN+ACK, uint8), proto: 6 (TCP, uint8), tos: 0 (uint8)
	// srcAS: 0 (uint16), dstAS: 0 (uint16)
	// srcMask: 24 (uint8), dstMask: 24 (uint8), pad2: 0 (uint16)
	buf.Write(net.ParseIP("192.168.1.50").To4())
	buf.Write(net.ParseIP("10.0.0.1").To4())
	buf.Write([]byte{0, 0, 0, 0})
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(2))
	_ = binary.Write(buf, binary.BigEndian, uint32(15))
	_ = binary.Write(buf, binary.BigEndian, uint32(1500))
	_ = binary.Write(buf, binary.BigEndian, uint32(2000))
	_ = binary.Write(buf, binary.BigEndian, uint32(8000))
	_ = binary.Write(buf, binary.BigEndian, uint16(44332))
	_ = binary.Write(buf, binary.BigEndian, uint16(80))
	buf.WriteByte(0)
	buf.WriteByte(0x12)
	buf.WriteByte(6)
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(100))
	_ = binary.Write(buf, binary.BigEndian, uint16(200))
	buf.WriteByte(24)
	buf.WriteByte(24)
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	cfg := &ParserConfig{
		RenormalizeSampling: true,
	}
	parser := NewFlowParser(cfg)

	records, err := parser.Parse(buf.Bytes(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error parsing NetFlow v5: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Type != "netflowv5" {
		t.Errorf("expected type 'netflowv5', got '%s'", rec.Type)
	}
	if rec.LanIP != "192.168.1.50" {
		t.Errorf("expected LanIP 192.168.1.50, got %s", rec.LanIP)
	}
	if rec.WanIP != "10.0.0.1" {
		t.Errorf("expected WanIP 10.0.0.1, got %s", rec.WanIP)
	}
	if rec.LanL4Port != 44332 || rec.WanL4Port != 80 {
		t.Errorf("expected ports 44332->80, got %d->%d", rec.LanL4Port, rec.WanL4Port)
	}
	if rec.L4Proto != 6 {
		t.Errorf("expected proto 6, got %d", rec.L4Proto)
	}
	if rec.Pkts != 15 || rec.Bytes != 1500 {
		t.Errorf("expected 15 pkts, 1500 bytes; got %d pkts, %d bytes", rec.Pkts, rec.Bytes)
	}
	if rec.TCPFlags != "SYN|ACK" {
		t.Errorf("expected tcpFlags 'SYN|ACK', got '%s'", rec.TCPFlags)
	}
}

func TestNetFlowV9TemplateAndData(t *testing.T) {
	cache := NewTemplateCache(30 * time.Minute)
	cfg := &ParserConfig{}
	parser := NewFlowParserWithCache(cfg, cache)

	// Step 1: Send a NetFlow v9 packet containing a Template FlowSet (FlowSet ID 0)
	// Template ID 256 with 6 fields:
	// 8 (IPV4_SRC_ADDR, 4 bytes)
	// 12 (IPV4_DST_ADDR, 4 bytes)
	// 7 (L4_SRC_PORT, 2 bytes)
	// 11 (L4_DST_PORT, 2 bytes)
	// 4 (PROTOCOL, 1 byte)
	// 1 (IN_BYTES, 4 bytes)
	tmplBuf := new(bytes.Buffer)
	// v9 Header: Version(9), Count(1 flowset), SysUptime(5000), UnixSecs(1700000000), Seq(1), SourceID(1)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(5000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1)) // SourceID / DomainID

	// FlowSet ID 0 (Template)
	// Length: 4 (flowset header) + 4 (template header: tmplID + fieldCount) + 6*4 (fields) = 32 bytes
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(0))  // FlowSet ID 0
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(32)) // FlowSet Length
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(256)) // Template ID
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(6))   // Field Count

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8))  // IPV4_SRC_ADDR
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12)) // IPV4_DST_ADDR
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(7))  // L4_SRC_PORT
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(11)) // L4_DST_PORT
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))  // PROTOCOL
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))  // IN_BYTES
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))

	records, err := parser.Parse(tmplBuf.Bytes(), "10.10.10.1")
	if err != nil {
		t.Fatalf("unexpected error parsing template packet: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 data records from template packet, got %d", len(records))
	}

	// Verify template exists in cache
	tmpl, ok := cache.Get("10.10.10.1", 1, 256)
	if !ok {
		t.Fatalf("template 256 not found in cache")
	}
	if len(tmpl.Fields) != 6 {
		t.Fatalf("expected 6 fields in template, got %d", len(tmpl.Fields))
	}

	// Step 2: Send a Data FlowSet referencing Template 256
	dataBuf := new(bytes.Buffer)
	// Header: Version(9), Count(1), SysUptime(6000), UnixSecs(1700000001), Seq(2), SourceID(1)
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(6000))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1)) // SourceID = 1

	// FlowSet ID 256 (Data FlowSet)
	// Length: 4 (header) + 17 bytes (data) + 3 bytes padding (to multiple of 4) = 24 bytes
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(256))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(24))

	// Data record fields:
	// src: 172.16.0.5 (4)
	// dst: 8.8.8.8 (4)
	// srcPort: 5353 (2)
	// dstPort: 53 (2)
	// proto: 17 (1)
	// in_bytes: 512 (4)
	dataBuf.Write(net.ParseIP("172.16.0.5").To4())
	dataBuf.Write(net.ParseIP("8.8.8.8").To4())
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(5353))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(53))
	dataBuf.WriteByte(17)
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(512))
	// 3 bytes padding
	dataBuf.Write([]byte{0, 0, 0})

	records, err = parser.Parse(dataBuf.Bytes(), "10.10.10.1")
	if err != nil {
		t.Fatalf("unexpected error parsing data packet: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 decoded record, got %d", len(records))
	}

	rec := records[0]
	if rec.Type != "netflowv9" {
		t.Errorf("expected type 'netflowv9', got '%s'", rec.Type)
	}
	if rec.LanIP != "172.16.0.5" || rec.WanIP != "8.8.8.8" {
		t.Errorf("expected IPs 172.16.0.5 -> 8.8.8.8, got %s -> %s", rec.LanIP, rec.WanIP)
	}
	if rec.LanL4Port != 5353 || rec.WanL4Port != 53 {
		t.Errorf("expected ports 5353 -> 53, got %d -> %d", rec.LanL4Port, rec.WanL4Port)
	}
	if rec.L4Proto != 17 {
		t.Errorf("expected proto 17 (UDP), got %d", rec.L4Proto)
	}
	if rec.Bytes != 512 {
		t.Errorf("expected 512 bytes, got %d", rec.Bytes)
	}
}

func TestIPFIXEnterpriseAndVariableLength(t *testing.T) {
	cache := NewTemplateCache(30 * time.Minute)
	cfg := &ParserConfig{}
	parser := NewFlowParserWithCache(cfg, cache)

	// Step 1: Send an IPFIX Template Set (Set ID 2)
	// Template ID 260 with:
	// - Field 8: sourceIPv4Address (4 bytes)
	// - Field 12: destinationIPv4Address (4 bytes)
	// - Field 301: isOpenPort (1 byte, Enterprise RedBorder PEN 0 or standard IE 301)
	// - Field 456: httpHostName (Variable-length: length = 65535 / 0xFFFF)
	tmplBuf := new(bytes.Buffer)
	// IPFIX Header (16 bytes): Version(10), Length(40), ExportTime(1700000000), Seq(1), DomainID(100)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(40)) // Total packet length (16 header + 24 set)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(100)) // Observation Domain ID

	// Set ID 2 (Template Set)
	// Length: 4 (header) + 4 (template record header: id=260, count=4) + 4*4 (fields) = 24 bytes
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(24))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(260))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8))      // sourceIPv4Address
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12))     // destinationIPv4Address
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(301))    // isOpenPort
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(456))    // httpHostName (variable length)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(0xFFFF)) // 0xFFFF denotes variable length in IPFIX

	records, err := parser.Parse(tmplBuf.Bytes(), "192.168.10.5")
	if err != nil {
		t.Fatalf("unexpected error parsing IPFIX template: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 data records, got %d", len(records))
	}

	// Step 2: Send Data Set for Template 260
	dataBuf := new(bytes.Buffer)
	hostStr := "example.redborder.com"

	// Data set length:
	// Set header: 4
	// Field 8 (4) + Field 12 (4) + Field 301 (1) = 9 bytes
	// Variable length field: 1-byte length prefix (len <= 254) + len(hostStr) = 1 + 21 = 22 bytes
	// Total data: 31 bytes. Set length = 4 + 31 = 35 bytes.
	// Total IPFIX packet: 16 (header) + 35 = 51 bytes.
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(51))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(100)) // Domain ID

	// Set ID 260
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(260))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(35))

	dataBuf.Write(net.ParseIP("192.168.1.100").To4())
	dataBuf.Write(net.ParseIP("10.0.0.25").To4())
	dataBuf.WriteByte(1) // isOpenPort = true (1)
	// Variable length: length < 255 is 1 byte
	dataBuf.WriteByte(byte(len(hostStr)))
	dataBuf.WriteString(hostStr)

	records, err = parser.Parse(dataBuf.Bytes(), "192.168.10.5")
	if err != nil {
		t.Fatalf("unexpected error parsing IPFIX data: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Type != "netflowv10" {
		t.Errorf("expected type 'netflowv10', got '%s'", rec.Type)
	}
	if rec.LanIP != "192.168.1.100" || rec.WanIP != "10.0.0.25" {
		t.Errorf("expected IPs 192.168.1.100 -> 10.0.0.25, got %s -> %s", rec.LanIP, rec.WanIP)
	}
	if !rec.IsOpenPort {
		t.Errorf("expected IsOpenPort true, got false")
	}
	if rec.Host != hostStr {
		t.Errorf("expected Host '%s', got '%s'", hostStr, rec.Host)
	}
}

func TestIPFIXTCPFlags183AndVLAN(t *testing.T) {
	cache := NewTemplateCache(30 * time.Minute)
	cfg := &ParserConfig{}
	parser := NewFlowParserWithCache(cfg, cache)

	// Step 1: Send IPFIX Template Set for Template 270
	// - Field 8: sourceIPv4Address (4 bytes)
	// - Field 12: destinationIPv4Address (4 bytes)
	// - Field 183: tcpControlBits (2 bytes)
	// - Field 58: vlanId (2 bytes)
	// - Field 60: ipVersion (1 byte)
	tmplBuf := new(bytes.Buffer)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(48)) // 16 header + 32 set
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(200))

	// Set ID 2 (Template Set)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(32))  // 4 set header + 4 record header + 6*4 field spec = 32
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(270)) // Template ID
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(6))   // 6 fields

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8))   // sourceIPv4Address
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12))  // destinationIPv4Address
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(183)) // tcpControlBits (IPFIX)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(58))  // vlanId
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(60))  // ipVersion
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(52))  // minimumTTL (min_ttl)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))

	_, err := parser.Parse(tmplBuf.Bytes(), "10.1.50.20")
	if err != nil {
		t.Fatalf("unexpected error parsing template: %v", err)
	}

	// Step 2: Send Data Set for Template 270
	dataBuf := new(bytes.Buffer)
	// Record data: 4 + 4 + 2 + 2 + 1 + 1 = 14 bytes.
	// Set length = 4 + 14 = 18 bytes.
	// Total packet: 16 + 18 = 34 bytes.
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(34))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(200))

	_ = binary.Write(dataBuf, binary.BigEndian, uint16(270)) // Template ID 270
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(18))  // Set Length

	dataBuf.Write(net.ParseIP("10.1.1.50").To4())
	dataBuf.Write(net.ParseIP("8.8.8.8").To4())
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(0x0012)) // SYN + ACK
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(100))    // VLAN 100
	dataBuf.WriteByte(4)                                    // ipVersion 4
	dataBuf.WriteByte(64)                                   // minimumTTL 64

	records, err := parser.Parse(dataBuf.Bytes(), "10.1.50.20")
	if err != nil {
		t.Fatalf("unexpected error parsing data: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.TCPFlags != "SYN|ACK" {
		t.Errorf("expected TCPFlags 'SYN|ACK', got '%s'", rec.TCPFlags)
	}
	if rec.LanVLAN != 100 {
		t.Errorf("expected LanVLAN 100, got %d", rec.LanVLAN)
	}
	if rec.IPProtocolVersion != 4 {
		t.Errorf("expected IPProtocolVersion 4, got %d", rec.IPProtocolVersion)
	}
	if rec.SrcTTL != 64 {
		t.Errorf("expected SrcTTL 64, got %d", rec.SrcTTL)
	}
}

func TestIPFIXCiscoAVCHTTPMetadata(t *testing.T) {
	cache := NewTemplateCache(30 * time.Minute)
	cfg := &ParserConfig{}
	parser := NewFlowParserWithCache(cfg, cache)

	// Step 1: Send IPFIX Template Set for Template 280
	// - Field 8: sourceIPv4Address (4 bytes)
	// - Field 12: destinationIPv4Address (4 bytes)
	// - Enterprise 9, Field 12235: variable length (0xFFFF)
	tmplBuf := new(bytes.Buffer)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(40)) // 16 header + 24 set
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(300))

	// Set ID 2 (Template Set)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(24))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(280)) // Template ID
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(3))   // 3 fields

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8))   // sourceIPv4Address
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12))  // destinationIPv4Address
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	// Enterprise 9, Field 12235 (high bit set for Enterprise: 0x8000 | 12235 = 0xAFCB)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(0x8000|12235))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(0xFFFF)) // variable length
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(9))      // Enterprise 9 (Cisco)

	_, err := parser.Parse(tmplBuf.Bytes(), "10.1.50.20")
	if err != nil {
		t.Fatalf("unexpected error parsing template: %v", err)
	}

	// Step 2: Send Data Set for Template 280
	dataBuf := new(bytes.Buffer)
	uaStr := "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0"
	// Payload for IE 12235: 6-byte prefix (0x03, 0x00, 0x00, 0x50, 0x34, 0x03) + uaStr
	uaPayload := append([]byte{0x03, 0x00, 0x00, 0x50, 0x34, 0x03}, []byte(uaStr)...)

	// Record: 4 (src) + 4 (dst) + 1 (len prefix) + len(uaPayload)
	recLen := 8 + 1 + len(uaPayload)
	setLen := 4 + recLen
	totalLen := 16 + setLen

	_ = binary.Write(dataBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(totalLen))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(300))

	_ = binary.Write(dataBuf, binary.BigEndian, uint16(280)) // Template ID 280
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(setLen))

	dataBuf.Write(net.ParseIP("10.1.1.50").To4())
	dataBuf.Write(net.ParseIP("8.8.8.8").To4())
	dataBuf.WriteByte(byte(len(uaPayload)))
	dataBuf.Write(uaPayload)

	records, err := parser.Parse(dataBuf.Bytes(), "10.1.50.20")
	if err != nil {
		t.Fatalf("unexpected error parsing data: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.HTTPUserAgent != uaStr {
		t.Errorf("expected HTTPUserAgent '%s', got '%s'", uaStr, rec.HTTPUserAgent)
	}
}

func TestSFlowV5Parsing(t *testing.T) {
	buf := new(bytes.Buffer)

	// sFlow datagram header:
	// Version: 5 (uint32)
	// Agent Address Type: 1 (IPv4, uint32)
	// Agent IP: 10.1.1.1 (4 bytes)
	// SubAgent ID: 1 (uint32)
	// Sequence Number: 100 (uint32)
	// Uptime: 500000 ms (uint32)
	// Num Samples: 1 (uint32)
	_ = binary.Write(buf, binary.BigEndian, uint32(5))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	buf.Write(net.ParseIP("10.1.1.1").To4())
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_ = binary.Write(buf, binary.BigEndian, uint32(100))
	_ = binary.Write(buf, binary.BigEndian, uint32(500000))
	_ = binary.Write(buf, binary.BigEndian, uint32(1)) // 1 sample

	// Sample 1: Flow Sample (Format 1)
	// Format: Enterprise 0, Format 1 -> 1 (uint32)
	// Sample Length: calculated below
	sampleBuf := new(bytes.Buffer)
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1001))   // Sequence Number
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(0x0102)) // Source ID (type 1, index 2)
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1000))   // Sampling Rate (1 in 1000)
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(50000))  // Sample Pool
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(0))      // Drops
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(10))     // Input Interface
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(20))     // Output Interface
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1))      // Num Flow Records: 1

	// Flow Record: Raw Packet Header (Format 1)
	// Enterprise 0, Format 1 -> 1 (uint32)
	recordBuf := new(bytes.Buffer)
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(1))      // Header Protocol: 1 (Ethernet-ISO88023)
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(64))     // Frame Length: 64 bytes
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(0))      // Stripped bytes: 0

	// Ethernet Frame payload:
	// Dst MAC (6): 00:11:22:33:44:55
	// Src MAC (6): 66:77:88:99:AA:BB
	// EtherType (2): 0x0800 (IPv4)
	// IPv4 Header (20 bytes):
	// Ver/IHL (0x45), TOS (0), TotalLen (50), ID (1), Flags/Offset (0), TTL (64), Proto (6 = TCP), Checksum (0)
	// Src IP: 192.168.5.10
	// Dst IP: 1.1.1.1
	// TCP Header:
	// SrcPort: 49152 (uint16), DstPort: 443 (uint16), Seq (0), Ack (0), Offset/Flags (0x5018 = ACK+PSH), Window (65535)
	frameBuf := new(bytes.Buffer)
	frameBuf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Dst MAC
	frameBuf.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}) // Src MAC
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0x0800))   // IPv4

	// IPv4 Header (20 bytes)
	frameBuf.WriteByte(0x45)
	frameBuf.WriteByte(0x00)
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(50))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))
	frameBuf.WriteByte(64)
	frameBuf.WriteByte(6) // TCP
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))
	frameBuf.Write(net.ParseIP("192.168.5.10").To4())
	frameBuf.Write(net.ParseIP("1.1.1.1").To4())

	// TCP Header (20 bytes)
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(49152))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(443))
	_ = binary.Write(frameBuf, binary.BigEndian, uint32(100))
	_ = binary.Write(frameBuf, binary.BigEndian, uint32(200))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0x5018)) // Data offset 5 (20 bytes), Flags 0x18 (ACK, PSH)
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(65535))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))

	frameBytes := frameBuf.Bytes()
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(len(frameBytes))) // Header length
	recordBuf.Write(frameBytes)
	// XDR 4-byte padding if needed
	pad := (4 - (len(frameBytes) % 4)) % 4
	for i := 0; i < pad; i++ {
		recordBuf.WriteByte(0)
	}

	// Write record format and length into sampleBuf
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // Record format: 1
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(recordBuf.Len()))
	sampleBuf.Write(recordBuf.Bytes())

	// Write sample format and length into buf
	_ = binary.Write(buf, binary.BigEndian, uint32(1)) // Sample format: 1 (Flow Sample)
	_ = binary.Write(buf, binary.BigEndian, uint32(sampleBuf.Len()))
	buf.Write(sampleBuf.Bytes())

	cfg := &ParserConfig{
		RenormalizeSampling: true,
	}
	parser := NewFlowParser(cfg)

	records, err := parser.Parse(buf.Bytes(), "10.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error parsing sFlow: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Type != "sflow" {
		t.Errorf("expected type 'sflow', got '%s'", rec.Type)
	}
	if rec.LanIP != "192.168.5.10" || rec.WanIP != "1.1.1.1" {
		t.Errorf("expected IPs 192.168.5.10 -> 1.1.1.1, got %s -> %s", rec.LanIP, rec.WanIP)
	}
	if rec.LanL4Port != 49152 || rec.WanL4Port != 443 {
		t.Errorf("expected ports 49152 -> 443, got %d -> %d", rec.LanL4Port, rec.WanL4Port)
	}
	if rec.L4Proto != 6 {
		t.Errorf("expected proto 6, got %d", rec.L4Proto)
	}
	if rec.ClientMAC != "66:77:88:99:aa:bb" || rec.ServerMAC != "00:11:22:33:44:55" {
		t.Errorf("expected MACs 66:77:88:99:aa:bb -> 00:11:22:33:44:55, got %s -> %s", rec.ClientMAC, rec.ServerMAC)
	}
	if rec.SrcTTL != 64 {
		t.Errorf("expected SrcTTL 64, got %d", rec.SrcTTL)
	}
	// Sampling rate is 1000, frame length is 64
	// With RenormalizeSampling: bytes = 64 * 1000 = 64000, pkts = 1 * 1000 = 1000
	if rec.Bytes != 64000 || rec.Pkts != 1000 {
		t.Errorf("expected renormalized 64000 bytes and 1000 pkts, got %d bytes and %d pkts", rec.Bytes, rec.Pkts)
	}
}

func TestExcludeFields(t *testing.T) {
	rec := &JSONFlowRecord{
		Type:       "netflowv5",
		LanIP:      "192.168.1.1",
		WanIP:      "8.8.8.8",
		LanL4Port:  1234,
		WanL4Port:  80,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		TCPFlags:   "SYN",
		Bytes:      100,
		Pkts:       1,
		Duration:   50,
	}

	cfg := &ParserConfig{
		ExcludeFields: []string{"client_mac", "tcp_flags", "duration"},
	}

	data, err := rec.ToFilteredJSON(cfg.ExcludeFields)
	if err != nil {
		t.Fatalf("failed to serialize record to JSON: %v", err)
	}

	jsonStr := string(data)
	if bytes.Contains(data, []byte("client_mac")) {
		t.Errorf("expected client_mac to be excluded, but found in: %s", jsonStr)
	}
	if bytes.Contains(data, []byte("tcp_flags")) {
		t.Errorf("expected tcp_flags to be excluded, but found in: %s", jsonStr)
	}
	if bytes.Contains(data, []byte("duration")) {
		t.Errorf("expected duration to be excluded, but found in: %s", jsonStr)
	}
	if !bytes.Contains(data, []byte("lan_ip")) {
		t.Errorf("expected lan_ip to remain, but missing from: %s", jsonStr)
	}
}


func TestIPv6DirectionAndAppID(t *testing.T) {
	cache := NewTemplateCache(10 * time.Minute)
	parser := NewFlowParserWithCache(&ParserConfig{}, cache)

	// Step 1: Send IPFIX Template Set with IPv6, Direction (61), and ApplicationID (95)
	tmplBuf := new(bytes.Buffer)
	// Set ID 2 (Template Set)
	// Set Header (4) + Template Header (4) + Field 27 (4) + Field 28 (4) + Field 61 (4) + Field 95 (4) = 24 bytes
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(40)) // 16 header + 24 set
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(200)) // DomainID

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(24))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(300)) // Template ID 300
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))   // 4 fields

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(27)) // sourceIPv6Address (16 bytes)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(16))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(28)) // destinationIPv6Address (16 bytes)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(16))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(61)) // direction (1 byte)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(95)) // applicationId (4 bytes: engine + id)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))

	_, err := parser.Parse(tmplBuf.Bytes(), "2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error parsing IPv6 IPFIX template: %v", err)
	}

	// Step 2: Send Data Set for Template 300
	dataBuf := new(bytes.Buffer)
	// Data length: 16 (srcIP) + 16 (dstIP) + 1 (direction) + 4 (appID: 3:53) = 37 bytes
	// Set length: 4 (header) + 37 = 41 bytes
	// Total packet: 16 (ipfix header) + 41 = 57 bytes
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(57))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(200))

	// Set ID 300
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(300))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(41))

	srcIPv6 := net.ParseIP("2001:db8:1::100")
	dstIPv6 := net.ParseIP("2001:db8:2::200")
	dataBuf.Write(srcIPv6)
	dataBuf.Write(dstIPv6)
	dataBuf.WriteByte(0)                           // direction = 0 (ingress)
	dataBuf.Write([]byte{0x03, 0x00, 0x00, 0x35}) // engine 3, app 53 -> "3:53"

	records, err := parser.Parse(dataBuf.Bytes(), "2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error parsing IPv6 IPFIX data: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.IPProtocolVersion != 6 {
		t.Errorf("expected IPProtocolVersion 6, got %d", rec.IPProtocolVersion)
	}
	if rec.LanIP != "2001:db8:1::100" || rec.WanIP != "2001:db8:2::200" {
		t.Errorf("expected IPv6 addresses %s -> %s, got %s -> %s", srcIPv6, dstIPv6, rec.LanIP, rec.WanIP)
	}
	if rec.Direction != "upstream" {
		t.Errorf("expected direction 'upstream', got '%s'", rec.Direction)
	}
	if rec.ApplicationID != "3:53" {
		t.Errorf("expected application_id '3:53', got '%s'", rec.ApplicationID)
	}

	// Verify flat JSON (no dynamic_fields)
	jsonData, err := rec.ToFilteredJSON(nil)
	if err != nil {
		t.Fatalf("failed to marshal to JSON: %v", err)
	}
	if bytes.Contains(jsonData, []byte("dynamic_fields")) {
		t.Errorf("expected flat JSON with no dynamic_fields, got: %s", string(jsonData))
	}
}

func TestTemplateCacheTTL(t *testing.T) {
	cache := NewTemplateCache(50 * time.Millisecond)
	cache.Set("1.1.1.1", 1, 256, Template{TemplateID: 256})

	tmpl, ok := cache.Get("1.1.1.1", 1, 256)
	if !ok || tmpl.TemplateID != 256 {
		t.Fatalf("expected template to be present")
	}

	time.Sleep(70 * time.Millisecond)

	_, ok = cache.Get("1.1.1.1", 1, 256)
	if ok {
		t.Errorf("expected template to be expired via Get()")
	}

	pruned := cache.PruneStale()
	if pruned != 1 {
		t.Errorf("expected 1 template pruned, got %d", pruned)
	}
}

func TestObservationDomainIDAndSpanPort(t *testing.T) {
	// Template with destination MAC and post-destination MAC
	tmplBuf := new(bytes.Buffer)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(10)) // IPFIX
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(32)) // length
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(400)) // Observation Domain ID = 400

	// Template set (setID = 2)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(16))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(260)) // Template ID = 260
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))   // 2 fields
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(80))  // IE_DESTINATION_MAC_ADDRESS
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(6))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(57))  // IE_POST_DESTINATION_MAC
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(6))

	cache := NewTemplateCache(10 * time.Minute)
	_, _ = ParseIPFIX(tmplBuf.Bytes(), "10.0.0.1", cache, &ParserConfig{})

	// Data set
	dataBuf := new(bytes.Buffer)
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(32))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(400)) // Observation Domain ID = 400

	_ = binary.Write(dataBuf, binary.BigEndian, uint16(260)) // Set ID = 260
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(16))  // 4 + 6 + 6 = 16
	dataBuf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Dest MAC (mirror / span)
	dataBuf.Write([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) // Post-Dest MAC (gateway)

	// 1. Without SpanPort: should use Post-Dest MAC (post-routing gateway MAC)
	recordsNoSpan, err := ParseIPFIX(dataBuf.Bytes(), "10.0.0.1", cache, &ParserConfig{SpanPort: false})
	if err != nil || len(recordsNoSpan) != 1 {
		t.Fatalf("unexpected error or record count: %v", err)
	}
	if recordsNoSpan[0].ObservationDomainID == nil || *recordsNoSpan[0].ObservationDomainID != 400 {
		t.Errorf("expected observation domain ID 400, got %v", recordsNoSpan[0].ObservationDomainID)
	}
	if recordsNoSpan[0].ServerMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected Post-Dest MAC 'aa:bb:cc:dd:ee:ff' without SpanPort, got %s", recordsNoSpan[0].ServerMAC)
	}

	// 2. With SpanPort: should prefer Ingress Dest MAC
	recordsSpan, err := ParseIPFIX(dataBuf.Bytes(), "10.0.0.1", cache, &ParserConfig{SpanPort: true})
	if err != nil || len(recordsSpan) != 1 {
		t.Fatalf("unexpected error or record count with SpanPort: %v", err)
	}
	if recordsSpan[0].ServerMAC != "00:11:22:33:44:55" {
		t.Errorf("expected Ingress Dest MAC '00:11:22:33:44:55' with SpanPort=true, got %s", recordsSpan[0].ServerMAC)
	}
}

func TestMalformedPackets(t *testing.T) {
	parser := NewFlowParser(&ParserConfig{})

	// Too short (< 4 bytes)
	_, err := parser.Parse([]byte{0x00, 0x05}, "127.0.0.1")
	if err == nil {
		t.Errorf("expected error on truncated packet")
	}

	// Unknown version
	_, err = parser.Parse([]byte{0x00, 0xFF, 0x00, 0x01}, "127.0.0.1")
	if err == nil {
		t.Errorf("expected error on unknown version 0x00FF")
	}

	// Truncated v5 header
	_, err = parser.Parse([]byte{0x00, 0x05, 0x00, 0x01, 0x00, 0x00}, "127.0.0.1")
	if err == nil {
		t.Errorf("expected error on truncated v5 header")
	}
}

func TestNetFlowV9OptionsTemplateAppAndInterfaceResolution(t *testing.T) {
	cache := NewTemplateCache(10 * time.Minute)

	// Step 1: NetFlow v9 Options Template (Template ID 257)
	// Scope length = 4 (e.g. system), Option length = 8 (AppID 95 len 8, AppName 96 len 16 -> total 24)
	optTmplBuf := new(bytes.Buffer)
	// Header (20 bytes)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(1)) // count = 1 FlowSet
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1000))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1)) // Source ID = 1

	// Options Template FlowSet (FlowSet ID = 1)
	// Length = 4 (FlowSet header) + 6 (opt tmpl header) + 4 (scope field) + 8 (option fields) = 22 -> pad to 24
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(1))  // FlowSet ID = 1
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(24)) // FlowSet Length = 24
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(257)) // Template ID = 257
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(4))   // Scope Length = 4
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(8))   // Option Length = 8
	// Scope field: System (type 1, len 4)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(4))
	// Option field 1: APPLICATION_ID (95, len 8)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(95))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(8))
	// Option field 2: APPLICATION_NAME (96, len 16)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(96))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(16))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(0)) // 2 bytes padding

	_, err := ParseNetFlowV9(optTmplBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse options template: %v", err)
	}

	// Verify template was cached and marked as option template
	tmpl, ok := cache.Get("10.10.1.4", 1, 257)
	if !ok {
		t.Fatalf("options template 257 was not cached")
	}
	if !tmpl.IsOptionTemplate {
		t.Errorf("expected IsOptionTemplate = true, got false")
	}

	// Step 2: Option Data FlowSet (Template ID 257)
	// Scope (4 bytes) + AppID (8 bytes: 0x0000304400003f43 = 53068615925571) + AppName (16 bytes: "DNS\x00...")
	optDataBuf := new(bytes.Buffer)
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1001))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1)) // Source ID = 1

	// Data FlowSet ID = 257, Length = 4 + 4 + 8 + 16 = 32
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(257))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(32))
	// Scope = 1
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1))
	// AppID (8 bytes) = 53068615925571 (0x0000304400003f43)
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(12356)) // 0x3044
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(16195)) // 0x3f43
	// AppName = "DNS" (16 bytes null padded)
	nameBytes := make([]byte, 16)
	copy(nameBytes, "DNS")
	optDataBuf.Write(nameBytes)

	optRecords, err := ParseNetFlowV9(optDataBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse option data flowset: %v", err)
	}
	// Option data flowsets should NOT produce traffic records
	if len(optRecords) != 0 {
		t.Errorf("expected 0 traffic records from option data flowset, got %d", len(optRecords))
	}

	// Step 3: Regular Data Template (Template ID 258)
	// SrcIP (8, 4), DstIP (12, 4), SrcPort (7, 2), DstPort (11, 2), Proto (4, 1), AppID (95, 8)
	dataTmplBuf := new(bytes.Buffer)
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(1002))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(1700000002))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(3))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(1)) // Source ID = 1

	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(0))  // Template FlowSet
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(32)) // Length
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(258)) // Template ID 258
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(6))   // 6 fields
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(8))   // SrcIP
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(12))  // DstIP
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(7))   // SrcPort
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(11))  // DstPort
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(4))   // Proto
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(95))  // AppID
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(8))

	_, err = ParseNetFlowV9(dataTmplBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse data template: %v", err)
	}

	// Step 4: Regular Traffic Flow (Template ID 258)
	trafficBuf := new(bytes.Buffer)
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1003))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1700000003))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(4))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1)) // Source ID = 1

	// Data FlowSet: ID 258, Length = 4 + 4 + 4 + 2 + 2 + 1 + 8 = 25 -> pad to 28
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(258))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(28))
	trafficBuf.Write(net.ParseIP("192.168.2.2").To4())
	trafficBuf.Write(net.ParseIP("8.8.8.8").To4())
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(58866))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(53))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(17)) // UDP
	// AppID (8 bytes: 0x0000304400003f43)
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(12356))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(16195))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(0)) // pad 3 bytes
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(0))

	flows, err := ParseNetFlowV9(trafficBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse traffic flow: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if flow.ApplicationName != "DNS" {
		t.Errorf("expected ApplicationName 'DNS', got '%s'", flow.ApplicationName)
	}
	if flow.ApplicationIDName != "DNS" {
		t.Errorf("expected ApplicationIDName 'DNS', got '%s'", flow.ApplicationIDName)
	}
	if flow.EngineIDName != "12356" {
		t.Errorf("expected EngineIDName '12356', got '%s'", flow.EngineIDName)
	}
	if flow.ApplicationID != "12356:16195" {
		t.Errorf("expected ApplicationID '12356:16195', got '%s'", flow.ApplicationID)
	}
}

func TestNetFlowV9InterfaceNameOptionsResolution(t *testing.T) {
	cache := NewTemplateCache(10 * time.Minute)

	// Step 1: NetFlow v9 Options Template for Interface Names (Template ID 259)
	// Scope: System (4 bytes), Options: INPUT_SNMP (10, 4 bytes), IF_NAME (82, 16 bytes)
	optTmplBuf := new(bytes.Buffer)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1000))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint32(1)) // Source ID = 1

	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(1))  // Options Template FlowSet
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(24)) // Length
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(259)) // Template ID = 259
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(4))   // Scope Length = 4
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(8))   // Option Length = 8
	// Scope: System
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(4))
	// Option 1: INPUT_SNMP (10, len 4)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(4))
	// Option 2: IF_NAME (82, len 16)
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(82))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(16))
	_ = binary.Write(optTmplBuf, binary.BigEndian, uint16(0)) // pad 2 bytes

	_, err := ParseNetFlowV9(optTmplBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse options template: %v", err)
	}

	// Step 2: Send Option Data: SNMP 34 -> "wan1"
	optDataBuf := new(bytes.Buffer)
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1001))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(259)) // Data FlowSet ID 259
	_ = binary.Write(optDataBuf, binary.BigEndian, uint16(28))  // 4 header + 4 scope + 4 snmp + 16 ifName = 28
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(1))   // Scope = 1
	_ = binary.Write(optDataBuf, binary.BigEndian, uint32(34))  // SNMP ifIndex = 34
	nameBytes := make([]byte, 16)
	copy(nameBytes, "wan1")
	optDataBuf.Write(nameBytes)

	_, err = ParseNetFlowV9(optDataBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse option data: %v", err)
	}

	// Step 3: Regular Template with INGRESS_INTERFACE (10, len 4) and EGRESS_INTERFACE (14, len 4)
	dataTmplBuf := new(bytes.Buffer)
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(1002))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(1700000002))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(3))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(0))  // Template FlowSet
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(20)) // Length
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(260)) // Template ID 260
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(3))   // 3 fields
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(8))   // SrcIP
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(10))  // INGRESS_INTERFACE
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(14))  // EGRESS_INTERFACE
	_ = binary.Write(dataTmplBuf, binary.BigEndian, uint16(4))

	_, err = ParseNetFlowV9(dataTmplBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse data template: %v", err)
	}

	// Step 4: Traffic Flow with LanInterface = 34
	trafficBuf := new(bytes.Buffer)
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1003))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1700000003))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(4))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(260))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(16)) // 4 header + 4 ip + 4 in + 4 out = 16
	trafficBuf.Write(net.ParseIP("10.0.0.1").To4())
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(34)) // INGRESS = 34
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(12)) // EGRESS = 12

	flows, err := ParseNetFlowV9(trafficBuf.Bytes(), "10.10.1.4", cache, &ParserConfig{})
	if err != nil {
		t.Fatalf("failed to parse traffic flow: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].LanInterfaceName != "wan1" {
		t.Errorf("expected LanInterfaceName 'wan1' resolved from options, got '%s'", flows[0].LanInterfaceName)
	}
	if flows[0].WanInterfaceName != "12" {
		t.Errorf("expected WanInterfaceName '12' (fallback to numeric), got '%s'", flows[0].WanInterfaceName)
	}
}

func TestApplicationDictionaryFallback(t *testing.T) {
	// Create temporary applications file
	tmpFile, err := os.CreateTemp("", "applications-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "# redBorder applications dictionary\n" +
		"dns                       50331701\n" +
		"http                      50331859\n" +
		"skype                     218103891\n" +
		"forti-dns                 53068615925571\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Verify parser loaded with ApplicationsFile resolves Cisco skype and FortiGate DNS
	parser := NewFlowParser(&ParserConfig{
		ApplicationsFile: tmpFile.Name(),
	})

	// 1. Cisco skype flow (Engine 13, App 83 = 218103891)
	tmplBuf := new(bytes.Buffer)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(100))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(0))  // Template FlowSet
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(28)) // Length
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(262))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(5))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8))   // SrcIP
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12))  // DstIP
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(7))   // SrcPort
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(11))  // DstPort
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(95))  // AppID (len 4)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))

	if _, err := parser.Parse(tmplBuf.Bytes(), "10.10.1.4"); err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	trafficBuf := new(bytes.Buffer)
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(101))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(262))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(20))
	trafficBuf.Write(net.ParseIP("192.168.2.2").To4())
	trafficBuf.Write(net.ParseIP("8.8.8.8").To4())
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(58866))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(443))
	// Cisco Engine 13 (0x0D), App 83 (0x000053) = 218103891
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(13))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(0))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(0))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(83))

	flows, err := parser.Parse(trafficBuf.Bytes(), "10.10.1.4")
	if err != nil {
		t.Fatalf("failed to parse flow: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].ApplicationName != "skype" {
		t.Errorf("expected ApplicationName 'skype', got '%s'", flows[0].ApplicationName)
	}
	if flows[0].ApplicationIDName != "skype" {
		t.Errorf("expected ApplicationIDName 'skype', got '%s'", flows[0].ApplicationIDName)
	}
	if flows[0].ApplicationID != "13:83" {
		t.Errorf("expected ApplicationID '13:83', got '%s'", flows[0].ApplicationID)
	}
}

func TestUnresolvedApplicationIDFormatting(t *testing.T) {
	// Without any option packets or dictionary,
	// Cisco 4-byte IDs format as engine:app (e.g. "13:83") and FortiGate as raw ID string, matching f2k.
	parser := NewFlowParser(&ParserConfig{})

	// 1. Template with AppID (len 4 for Cisco)
	tmplBuf := new(bytes.Buffer)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(100))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(0))  // Template FlowSet
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(28)) // Length
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(261))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(5))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8))   // SrcIP
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12))  // DstIP
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(7))   // SrcPort
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(11))  // DstPort
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(95))  // AppID (len 4)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))

	_, err := parser.Parse(tmplBuf.Bytes(), "10.10.1.4")
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	// 2. Traffic Flow: Cisco Engine 13, App 83 (0x0D000053)
	trafficBuf := new(bytes.Buffer)
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(9))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(101))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint32(1))

	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(261))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(20)) // 4 header + 4 + 4 + 2 + 2 + 4 = 20
	trafficBuf.Write(net.ParseIP("192.168.2.2").To4())
	trafficBuf.Write(net.ParseIP("8.8.8.8").To4())
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(58866))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint16(443))
	// Cisco Engine 13 (0x0D), App 83 (0x000053)
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(13))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(0))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(0))
	_ = binary.Write(trafficBuf, binary.BigEndian, uint8(83))

	flows, err := parser.Parse(trafficBuf.Bytes(), "10.10.1.4")
	if err != nil {
		t.Fatalf("failed to parse traffic flow: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].ApplicationID != "13:83" {
		t.Errorf("expected ApplicationID '13:83', got '%s'", flows[0].ApplicationID)
	}
	if flows[0].ApplicationName != "13:83" {
		t.Errorf("expected ApplicationName '13:83' fallback, got '%s'", flows[0].ApplicationName)
	}
}
