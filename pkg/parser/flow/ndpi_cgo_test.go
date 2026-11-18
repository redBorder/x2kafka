//go:build ndpi && cgo

package flow

import (
	"testing"
	"time"
)

// A DNS query is identified from a single packet, so it exercises the real nDPI path.
func TestNDPIClassifiesDNSQuery(t *testing.T) {
	classifier, err := NewNDPIClassifier()
	if err != nil {
		t.Fatalf("NewNDPIClassifier failed: %v", err)
	}
	defer classifier.Close()

	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header, 1 question
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // example.com
		0x00, 0x01, 0x00, 0x01, // A, IN
	}
	pkt := buildIPv4Packet(17, "192.168.5.10", "192.168.5.1", 50000, 53, query)

	m := classifier.Classify(pkt, time.Now().UnixMilli())
	if m.Name != "DNS" {
		t.Errorf("expected DNS, got %+v", m)
	}
	if m.Confidence != AppByDPI {
		t.Errorf("expected a payload detection, got confidence %d", m.Confidence)
	}
}

// A mid-flow TCP packet carries nothing to inspect: nDPI must still return its guess.
func TestNDPIGuessesMidFlowPacket(t *testing.T) {
	classifier, err := NewNDPIClassifier()
	if err != nil {
		t.Fatalf("NewNDPIClassifier failed: %v", err)
	}
	defer classifier.Close()

	pkt := buildIPv4Packet(6, "192.168.5.10", "192.168.5.20", 50000, 22, nil)
	m := classifier.Classify(pkt, time.Now().UnixMilli())
	if m.Name == "" || m.Confidence == AppByDPI {
		t.Errorf("expected a guessed protocol for port 22, got %+v", m)
	}
}
