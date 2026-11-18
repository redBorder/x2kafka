package flow

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// buildIPv4Packet builds an IPv4 packet (from the IP header on) with a TCP or UDP header.
func buildIPv4Packet(proto uint8, src, dst string, sport, dport uint16, payload []byte) []byte {
	l4 := new(bytes.Buffer)
	_ = binary.Write(l4, binary.BigEndian, sport)
	_ = binary.Write(l4, binary.BigEndian, dport)
	if proto == 6 {
		_ = binary.Write(l4, binary.BigEndian, uint32(100))    // seq
		_ = binary.Write(l4, binary.BigEndian, uint32(200))    // ack
		_ = binary.Write(l4, binary.BigEndian, uint16(0x5018)) // offset 5, ACK+PSH
		_ = binary.Write(l4, binary.BigEndian, uint16(65535))  // window
		_ = binary.Write(l4, binary.BigEndian, uint32(0))      // checksum + urgent
	} else {
		_ = binary.Write(l4, binary.BigEndian, uint16(8+len(payload)))
		_ = binary.Write(l4, binary.BigEndian, uint16(0))
	}
	l4.Write(payload)

	ip := new(bytes.Buffer)
	ip.WriteByte(0x45)
	ip.WriteByte(0x00)
	_ = binary.Write(ip, binary.BigEndian, uint16(20+l4.Len()))
	_ = binary.Write(ip, binary.BigEndian, uint32(0)) // id, flags, offset
	ip.WriteByte(64)
	ip.WriteByte(proto)
	_ = binary.Write(ip, binary.BigEndian, uint16(0))
	ip.Write(net.ParseIP(src).To4())
	ip.Write(net.ParseIP(dst).To4())
	ip.Write(l4.Bytes())
	return ip.Bytes()
}

// buildSFlowDatagram wraps each IPv4 packet in an Ethernet frame inside its own flow sample.
func buildSFlowDatagram(packets ...[]byte) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint32(5)) // version
	_ = binary.Write(buf, binary.BigEndian, uint32(1)) // agent address type: IPv4
	buf.Write(net.ParseIP("10.1.1.1").To4())
	_ = binary.Write(buf, binary.BigEndian, uint32(1))            // sub agent
	_ = binary.Write(buf, binary.BigEndian, uint32(100))          // sequence
	_ = binary.Write(buf, binary.BigEndian, uint32(500000))       // uptime
	_ = binary.Write(buf, binary.BigEndian, uint32(len(packets))) // samples

	for _, pkt := range packets {
		frame := new(bytes.Buffer)
		frame.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
		frame.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB})
		_ = binary.Write(frame, binary.BigEndian, uint16(0x0800))
		frame.Write(pkt)

		record := new(bytes.Buffer)
		_ = binary.Write(record, binary.BigEndian, uint32(1))           // header protocol: Ethernet
		_ = binary.Write(record, binary.BigEndian, uint32(frame.Len())) // frame length
		_ = binary.Write(record, binary.BigEndian, uint32(0))           // stripped
		_ = binary.Write(record, binary.BigEndian, uint32(frame.Len())) // header length
		record.Write(frame.Bytes())
		for i := 0; i < (4-frame.Len()%4)%4; i++ {
			record.WriteByte(0)
		}

		sample := new(bytes.Buffer)
		_ = binary.Write(sample, binary.BigEndian, uint32(1))  // sequence
		_ = binary.Write(sample, binary.BigEndian, uint32(2))  // source id
		_ = binary.Write(sample, binary.BigEndian, uint32(1))  // sampling rate
		_ = binary.Write(sample, binary.BigEndian, uint32(1))  // sample pool
		_ = binary.Write(sample, binary.BigEndian, uint32(0))  // drops
		_ = binary.Write(sample, binary.BigEndian, uint32(10)) // input
		_ = binary.Write(sample, binary.BigEndian, uint32(20)) // output
		_ = binary.Write(sample, binary.BigEndian, uint32(1))  // records
		_ = binary.Write(sample, binary.BigEndian, uint32(1))  // record format: raw header
		_ = binary.Write(sample, binary.BigEndian, uint32(record.Len()))
		sample.Write(record.Bytes())

		_ = binary.Write(buf, binary.BigEndian, uint32(1)) // sample format: flow sample
		_ = binary.Write(buf, binary.BigEndian, uint32(sample.Len()))
		buf.Write(sample.Bytes())
	}
	return buf.Bytes()
}

// fakeClassifier answers from a table keyed by the packet's source IP.
type fakeClassifier struct {
	bySrc  map[string]AppMatch
	calls  int
	closed bool
}

func (f *fakeClassifier) Classify(l3 []byte, _ int64) AppMatch {
	f.calls++
	return f.bySrc[net.IP(l3[12:16]).String()]
}

func (f *fakeClassifier) Close() { f.closed = true }

func writeApplicationsFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "applications-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestSFlowPortMappingFallback(t *testing.T) {
	// 50332091 = engine 3 (L4 port) << 24 | 443
	parser := NewFlowParser(&ParserConfig{
		ApplicationsFile: writeApplicationsFile(t, "https 50332091\n"),
	})

	data := buildSFlowDatagram(
		buildIPv4Packet(6, "192.168.5.10", "1.1.1.1", 49152, 443, nil),
		buildIPv4Packet(6, "192.168.5.10", "1.1.1.1", 49152, 8443, nil),
	)
	records, err := parser.Parse(data, "10.1.1.1")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	rec := records[0]
	if rec.ApplicationIDName != "https" || rec.ApplicationName != "https" {
		t.Errorf("expected application https, got id_name=%q name=%q", rec.ApplicationIDName, rec.ApplicationName)
	}
	if rec.ApplicationID != "3:443" || rec.EngineIDName != "3" {
		t.Errorf("expected 3:443 with engine 3, got %q engine %q", rec.ApplicationID, rec.EngineIDName)
	}
	if records[1].ApplicationIDName != "" {
		t.Errorf("port without dictionary entry must stay unclassified, got %q", records[1].ApplicationIDName)
	}

	out, err := rec.ToFilteredJSON(nil)
	if err != nil {
		t.Fatalf("ToFilteredJSON failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["application_id_name"] != "https" {
		t.Errorf("application_id_name missing in JSON: %s", out)
	}
	if rec.l3 != nil || strings.Contains(string(out), "l3") {
		t.Errorf("sampled packet bytes must not be kept or emitted")
	}
}

func TestSFlowNDPIClassification(t *testing.T) {
	fake := &fakeClassifier{bySrc: map[string]AppMatch{
		"192.168.5.10": {Name: "YouTube", ID: 124, Confidence: AppByDPI},
		"192.168.5.12": {Name: "Google", ID: 126, Confidence: AppByIP},
	}}
	parser := NewFlowParser(&ParserConfig{
		ApplicationsFile: writeApplicationsFile(t, "https 50332091\n"),
	})
	parser.ndpi = fake
	parser.appCache = newServerAppCache(time.Minute)

	data := buildSFlowDatagram(
		// Payload detection towards 8.8.8.8:443, remembered for that server.
		buildIPv4Packet(6, "192.168.5.10", "8.8.8.8", 49152, 443, nil),
		// Unknown to nDPI: another client inherits the detection, also on the reply direction.
		buildIPv4Packet(6, "192.168.5.11", "8.8.8.8", 50000, 443, nil),
		buildIPv4Packet(6, "8.8.8.8", "192.168.5.11", 443, 50000, nil),
		// nDPI guess by IP for a server without cached detection.
		buildIPv4Packet(6, "192.168.5.12", "9.9.9.9", 50001, 443, nil),
		// Nothing from nDPI nor the cache: port mapping.
		buildIPv4Packet(6, "192.168.5.13", "9.9.9.9", 50002, 443, nil),
	)
	records, err := parser.Parse(data, "10.1.1.1")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(records) != 5 {
		t.Fatalf("expected 5 records, got %d", len(records))
	}
	if fake.calls != 5 {
		t.Errorf("expected one nDPI call per sample, got %d", fake.calls)
	}

	want := []struct{ name, id, engine string }{
		{"youtube", "13:124", "13"},
		{"youtube", "13:124", "13"},
		{"youtube", "13:124", "13"},
		{"google", "13:126", "13"},
		{"https", "3:443", "3"},
	}
	for i, w := range want {
		rec := records[i]
		if rec.ApplicationIDName != w.name || rec.ApplicationID != w.id || rec.EngineIDName != w.engine {
			t.Errorf("record %d: expected %s/%s/%s, got %s/%s/%s", i, w.name, w.id, w.engine,
				rec.ApplicationIDName, rec.ApplicationID, rec.EngineIDName)
		}
	}

	// The reply sample is still oriented by home_nets after being classified.
	if records[2].LanIP != "192.168.5.11" || records[2].Direction != "downstream" {
		t.Errorf("expected downstream record with lan_ip 192.168.5.11, got %s %s", records[2].Direction, records[2].LanIP)
	}

	parser.Close()
	if !fake.closed {
		t.Errorf("Close must release the classifier")
	}
}

func TestServerAppCache(t *testing.T) {
	now := time.Now()
	cache := newServerAppCache(time.Minute)
	key := serverKey{ip: "8.8.8.8", port: 443, proto: 6}

	cache.put(key, "YouTube", 124, now)
	if got, ok := cache.get(key, now.Add(30*time.Second)); !ok || got.name != "YouTube" {
		t.Errorf("expected cached YouTube, got %+v ok=%v", got, ok)
	}
	if _, ok := cache.get(key, now.Add(2*time.Minute)); ok {
		t.Errorf("entry must expire after the TTL")
	}

	// Two ephemeral ports: no side can be taken as the server.
	rec := &JSONFlowRecord{L4Proto: 6, LanIP: "10.0.0.1", WanIP: "10.0.0.2", LanL4Port: 40000, WanL4Port: 50000}
	if _, ok := serverEndpoint(rec); ok {
		t.Errorf("ephemeral ports must not be used as cache key")
	}
	// ICMP has no ports.
	if _, ok := serverEndpoint(&JSONFlowRecord{L4Proto: 1, LanIP: "10.0.0.1", WanIP: "10.0.0.2"}); ok {
		t.Errorf("only TCP and UDP have a server endpoint")
	}
}

func TestFitL3Length(t *testing.T) {
	full := buildIPv4Packet(17, "192.168.5.10", "8.8.8.8", 50000, 53, bytes.Repeat([]byte{0xAB}, 200))
	if got := fitL3Length(full); &got[0] != &full[0] {
		t.Errorf("a complete packet must be returned untouched")
	}

	truncated := full[:128]
	fitted := fitL3Length(truncated)
	if got := binary.BigEndian.Uint16(fitted[2:4]); got != 128 {
		t.Errorf("expected IP total length 128, got %d", got)
	}
	if got := binary.BigEndian.Uint16(fitted[24:26]); got != 108 {
		t.Errorf("expected UDP length 108, got %d", got)
	}
	if got := binary.BigEndian.Uint16(truncated[2:4]); got != 228 {
		t.Errorf("the sampled packet must not be modified, total length is now %d", got)
	}

	// IPv6: 40-byte header claiming 200 bytes of UDP payload, only 60 captured.
	v6 := make([]byte, 100)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], 200)
	v6[6] = 17
	fitted = fitL3Length(v6)
	if got := binary.BigEndian.Uint16(fitted[4:6]); got != 60 {
		t.Errorf("expected IPv6 payload length 60, got %d", got)
	}
	if got := binary.BigEndian.Uint16(fitted[44:46]); got != 60 {
		t.Errorf("expected UDP length 60, got %d", got)
	}
}
