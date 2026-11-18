package listener

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"x2kafka/pkg/config"
	"x2kafka/pkg/kafka"
)

func TestFlowListenerNetFlowV5UDP(t *testing.T) {
	// Find a free UDP port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	cfg := config.ListenerConfig{
		Name:          "test-flow-v5",
		Proto:         "netflow",
		Bind:          "127.0.0.1",
		Port:          port,
		Topic:         "rb_flow",
		ExcludeFields: []string{"duration", "tcp_flags"},
		EnrichmentMap: map[string]map[string]interface{}{
			"127.0.0.1": {
				"sensor_uuid": "test-uuid-1234",
				"sensor_name": "test-sensor",
			},
		},
	}

	l := NewFlowListener(cfg)
	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("failed to start FlowListener: %v", err)
	}
	defer func() { _ = l.Stop() }()

	// Wait briefly for listener to be active
	time.Sleep(50 * time.Millisecond)

	// Build a small NetFlow v5 packet
	buf := new(bytes.Buffer)
	// Header (24 bytes)
	_ = binary.Write(buf, binary.BigEndian, uint16(5))
	_ = binary.Write(buf, binary.BigEndian, uint16(1)) // count = 1
	_ = binary.Write(buf, binary.BigEndian, uint32(5000))
	_ = binary.Write(buf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// Record 1 (48 bytes)
	buf.Write(net.ParseIP("192.168.1.10").To4())
	buf.Write(net.ParseIP("8.8.8.8").To4())
	buf.Write([]byte{0, 0, 0, 0})
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(2))
	_ = binary.Write(buf, binary.BigEndian, uint32(5))
	_ = binary.Write(buf, binary.BigEndian, uint32(300))
	_ = binary.Write(buf, binary.BigEndian, uint32(1000))
	_ = binary.Write(buf, binary.BigEndian, uint32(4000))
	_ = binary.Write(buf, binary.BigEndian, uint16(54321))
	_ = binary.Write(buf, binary.BigEndian, uint16(53))
	buf.WriteByte(0)
	buf.WriteByte(0x10) // ACK
	buf.WriteByte(17)   // UDP
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	buf.WriteByte(24)
	buf.WriteByte(24)
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// Send UDP packet
	targetAddr, err := net.ResolveUDPAddr("udp", l.udpConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to resolve target UDP: %v", err)
	}

	senderConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		t.Fatalf("failed to dial target UDP: %v", err)
	}
	defer senderConn.Close()

	if _, err := senderConn.Write(buf.Bytes()); err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	// Receive message
	select {
	case msg := <-msgChan:
		if msg.Topic != "rb_flow" {
			t.Errorf("expected topic 'rb_flow', got '%s'", msg.Topic)
		}
		jsonStr := string(msg.Value)
		if !bytes.Contains(msg.Value, []byte("192.168.1.10")) {
			t.Errorf("expected LanIP in JSON: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte("test-uuid-1234")) {
			t.Errorf("expected enriched sensor_uuid in JSON: %s", jsonStr)
		}
		if bytes.Contains(msg.Value, []byte("tcp_flags")) {
			t.Errorf("expected tcp_flags to be excluded from JSON: %s", jsonStr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for flow message on msgChan")
	}
}

func TestFlowListenerIPFilter(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	// Blacklist 127.0.0.1
	cfg := config.ListenerConfig{
		Name:         "test-flow-blocked",
		Proto:        "netflow",
		Bind:         "127.0.0.1",
		Port:         port,
		BlacklistIPs: []string{"127.0.0.1"},
	}

	l := NewFlowListener(cfg)
	msgChan := make(chan *kafka.Message, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	targetAddr, _ := net.ResolveUDPAddr("udp", l.udpConn.LocalAddr().String())
	senderConn, _ := net.DialUDP("udp", nil, targetAddr)
	defer senderConn.Close()

	// Send dummy packet
	_, _ = senderConn.Write([]byte{0x00, 0x05, 0x00, 0x00})

	select {
	case <-msgChan:
		t.Fatalf("unexpected message received from blacklisted IP")
	case <-time.After(300 * time.Millisecond):
		// Expected: nothing received
	}
}

func TestFlowListenerHomeNetsOrientation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	// Configure a custom HomeNet: 198.51.100.0/24 (TEST-NET-2)
	cfg := config.ListenerConfig{
		Name:     "test-flow-homenets",
		Proto:    "netflow",
		Bind:     "127.0.0.1",
		Port:     port,
		Topic:    "rb_flow",
		HomeNets: []string{"198.51.100.0/24"},
	}

	l := NewFlowListener(cfg)
	msgChan := make(chan *kafka.Message, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	// Send NetFlow v5 where src is WAN (8.8.8.8) and dst is LAN (198.51.100.42)
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint16(5))
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint32(5000))
	_ = binary.Write(buf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// Record: src=8.8.8.8, dst=198.51.100.42 (downstream)
	buf.Write(net.ParseIP("8.8.8.8").To4())
	buf.Write(net.ParseIP("198.51.100.42").To4())
	buf.Write([]byte{0, 0, 0, 0})
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(2))
	_ = binary.Write(buf, binary.BigEndian, uint32(5))
	_ = binary.Write(buf, binary.BigEndian, uint32(300))
	_ = binary.Write(buf, binary.BigEndian, uint32(1000))
	_ = binary.Write(buf, binary.BigEndian, uint32(4000))
	_ = binary.Write(buf, binary.BigEndian, uint16(443))
	_ = binary.Write(buf, binary.BigEndian, uint16(50123))
	buf.WriteByte(0)
	buf.WriteByte(0x10)
	buf.WriteByte(6) // TCP
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	buf.WriteByte(24)
	buf.WriteByte(24)
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	targetAddr, _ := net.ResolveUDPAddr("udp", l.udpConn.LocalAddr().String())
	senderConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer senderConn.Close()

	if _, err := senderConn.Write(buf.Bytes()); err != nil {
		t.Fatalf("failed to send: %v", err)
	}

	select {
	case msg := <-msgChan:
		jsonStr := string(msg.Value)
		// Model A orientation: lan_ip is ALWAYS home_net (198.51.100.42), wan_ip is external (8.8.8.8), direction is downstream
		if !bytes.Contains(msg.Value, []byte(`"lan_ip":"198.51.100.42"`)) {
			t.Errorf("expected lan_ip to be oriented to 198.51.100.42: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"wan_ip":"8.8.8.8"`)) {
			t.Errorf("expected wan_ip to be oriented to 8.8.8.8: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"direction":"downstream"`)) {
			t.Errorf("expected direction to be downstream: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"lan_l4_port":50123`)) {
			t.Errorf("expected lan_l4_port 50123: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"wan_l4_port":443`)) {
			t.Errorf("expected wan_l4_port 443: %s", jsonStr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for flow message")
	}
}

func TestFlowListenerObservationIDEnrichment(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	cfg := config.ListenerConfig{
		Name:  "test-flow-obs",
		Proto: "ipfix",
		Bind:  "127.0.0.1",
		Port:  port,
		Topic: "rb_flow",
		EnrichmentMap: map[string]map[string]interface{}{
			"127.0.0.1:100": {
				"sensor_uuid": "obs-uuid-100",
				"sensor_name": "obs-sensor-100",
			},
			"default": {
				"sensor_uuid": "obs-uuid-default",
				"sensor_name": "obs-sensor-default",
			},
		},
	}

	l := NewFlowListener(cfg)
	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("failed to start FlowListener: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	// Send Template with domainID = 100
	tmplBuf := new(bytes.Buffer)
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(32))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1700000000))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint32(100)) // Observation Domain ID = 100

	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(16))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(256))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(8)) // src IPv4
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(12)) // dst IPv4
	_ = binary.Write(tmplBuf, binary.BigEndian, uint16(4))

	targetAddr, _ := net.ResolveUDPAddr("udp", l.udpConn.LocalAddr().String())
	senderConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer senderConn.Close()

	if _, err := senderConn.Write(tmplBuf.Bytes()); err != nil {
		t.Fatalf("failed to send template: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Send Data with domainID = 100
	dataBuf := new(bytes.Buffer)
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(10))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(28)) // 16 header + 12 set = 28
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(1700000001))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(dataBuf, binary.BigEndian, uint32(100)) // Observation Domain ID = 100

	_ = binary.Write(dataBuf, binary.BigEndian, uint16(256))
	_ = binary.Write(dataBuf, binary.BigEndian, uint16(12))
	_, _ = dataBuf.Write(net.ParseIP("10.0.0.1").To4())
	_, _ = dataBuf.Write(net.ParseIP("10.0.0.2").To4())

	if _, err := senderConn.Write(dataBuf.Bytes()); err != nil {
		t.Fatalf("failed to send data: %v", err)
	}

	select {
	case msg := <-msgChan:
		jsonStr := string(msg.Value)
		if !bytes.Contains(msg.Value, []byte(`"observation_domain_id":100`)) {
			t.Errorf("expected observation_domain_id 100: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"sensor_uuid":"obs-uuid-100"`)) {
			t.Errorf("expected sensor_uuid obs-uuid-100 from per-observation enrichment: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"sensor_name":"obs-sensor-100"`)) {
			t.Errorf("expected sensor_name obs-sensor-100: %s", jsonStr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for flow message")
	}
}

func TestFlowListenerSFlowFilteringAndEnrichment(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	cfg := config.ListenerConfig{
		Name:          "test-sflow-enrich",
		Proto:         "sflow",
		Bind:          "127.0.0.1",
		Port:          port,
		Topic:         "rb_flow",
		AllowedIPs:    []string{"127.0.0.1"},
		EnrichmentKey: "sensor_ip",
		EnrichmentMap: map[string]map[string]interface{}{
			"10.1.1.1": {
				"sensor_uuid": "sflow-agent-uuid-555",
				"sensor_name": "switch-core-01",
			},
		},
	}

	l := NewFlowListener(cfg)
	msgChan := make(chan *kafka.Message, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("failed to start sflow listener: %v", err)
	}
	defer func() { _ = l.Stop() }()
	time.Sleep(50 * time.Millisecond)

	// Build sflow packet with agent IP 10.1.1.1
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint32(5))
	_ = binary.Write(buf, binary.BigEndian, uint32(1)) // IPv4
	buf.Write(net.ParseIP("10.1.1.1").To4())
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_ = binary.Write(buf, binary.BigEndian, uint32(100))
	_ = binary.Write(buf, binary.BigEndian, uint32(500000))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))

	sampleBuf := new(bytes.Buffer)
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1001))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(0x0102))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1000))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(50000))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(0))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(10))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(20))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1))

	recordBuf := new(bytes.Buffer)
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(64))
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(0))

	frameBuf := new(bytes.Buffer)
	frameBuf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	frameBuf.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB})
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0x0800))
	frameBuf.WriteByte(0x45)
	frameBuf.WriteByte(0x00)
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(50))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(1))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))
	frameBuf.WriteByte(64)
	frameBuf.WriteByte(6)
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))
	frameBuf.Write(net.ParseIP("192.168.5.10").To4())
	frameBuf.Write(net.ParseIP("1.1.1.1").To4())
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(49152))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(443))
	_ = binary.Write(frameBuf, binary.BigEndian, uint32(100))
	_ = binary.Write(frameBuf, binary.BigEndian, uint32(200))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0x5018))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(65535))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))
	_ = binary.Write(frameBuf, binary.BigEndian, uint16(0))

	frameBytes := frameBuf.Bytes()
	_ = binary.Write(recordBuf, binary.BigEndian, uint32(len(frameBytes)))
	recordBuf.Write(frameBytes)
	pad := (4 - (len(frameBytes) % 4)) % 4
	for i := 0; i < pad; i++ {
		recordBuf.WriteByte(0)
	}

	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1))
	_ = binary.Write(sampleBuf, binary.BigEndian, uint32(recordBuf.Len()))
	sampleBuf.Write(recordBuf.Bytes())

	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_ = binary.Write(buf, binary.BigEndian, uint32(sampleBuf.Len()))
	buf.Write(sampleBuf.Bytes())

	targetAddr, _ := net.ResolveUDPAddr("udp", l.udpConn.LocalAddr().String())
	senderConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer senderConn.Close()

	if _, err := senderConn.Write(buf.Bytes()); err != nil {
		t.Fatalf("failed to send sflow packet: %v", err)
	}

	select {
	case msg := <-msgChan:
		jsonStr := string(msg.Value)
		if !bytes.Contains(msg.Value, []byte(`"sensor_uuid":"sflow-agent-uuid-555"`)) {
			t.Errorf("expected sensor_uuid sflow-agent-uuid-555: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"sensor_name":"switch-core-01"`)) {
			t.Errorf("expected sensor_name switch-core-01: %s", jsonStr)
		}
		if !bytes.Contains(msg.Value, []byte(`"sensor_ip":"10.1.1.1"`)) {
			t.Errorf("expected sensor_ip 10.1.1.1: %s", jsonStr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for sflow message")
	}
}

func TestSensorHomeNets(t *testing.T) {
	got := sensorHomeNets(map[string]map[string]interface{}{
		"10.0.0.1": {"sensor_name": "a", "home_nets": []interface{}{"192.168.0.0/16", "10.0.0.0/8"}},
		"10.0.0.2": {"sensor_name": "b", "home_nets": "172.16.0.0/12"},
		"10.0.0.3": {"sensor_name": "c"},
		"10.0.0.4": {
			"observations_id": map[string]interface{}{
				"100":     map[string]interface{}{"enrichment": map[string]interface{}{"home_nets": []interface{}{"10.1.0.0/16"}}},
				"default": map[string]interface{}{"home_nets": []interface{}{"10.2.0.0/16"}},
			},
		},
	})

	want := map[string][]string{
		"10.0.0.1":     {"192.168.0.0/16", "10.0.0.0/8"},
		"10.0.0.2":     {"172.16.0.0/12"},
		"10.0.0.4:100": {"10.1.0.0/16"},
		"10.0.0.4":     {"10.2.0.0/16"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d sensors with home_nets, got %d: %v", len(want), len(got), got)
	}
	for key, nets := range want {
		if strings.Join(got[key], ",") != strings.Join(nets, ",") {
			t.Errorf("sensor %s: expected %v, got %v", key, nets, got[key])
		}
	}

	if sensorHomeNets(map[string]map[string]interface{}{"10.0.0.3": {"sensor_name": "c"}}) != nil {
		t.Errorf("expected nil without any sensor home_nets")
	}
}
