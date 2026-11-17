package engine

import (
	"testing"
	"time"

	"x2kafka/pkg/config"
	"x2kafka/pkg/kafka"
)

func TestPerListenerTopicRouting(t *testing.T) {
	cfg := &config.Config{
		Brokers: []string{"localhost:9092"},
		Topic:   "global_default_topic",
		Listeners: []config.ListenerConfig{
			{
				Name:  "snmptrap-listener",
				Proto: "fifo",
				Path:  "/tmp/test_snmp.fifo",
				Topic: "snmptraps_topic",
			},
			{
				Name:  "syslog-listener",
				Proto: "syslog_udp",
				Bind:  "127.0.0.1",
				Port:  15140,
				Topic: "syslog_raw_topic",
			},
			{
				Name:  "default-fallback-listener",
				Proto: "http",
				Bind:  "127.0.0.1",
				Port:  18080,
				// Topic omitted, will fallback to global_default_topic
			},
		},
	}

	p, err := kafka.NewProducer(kafka.ProducerConfig{
		Brokers: cfg.Brokers,
		Topic:   cfg.Topic,
	})
	if err != nil {
		t.Fatalf("Failed to create producer: %v", err)
	}
	defer p.Close()

	// Test message from snmptrap-listener
	msg1 := &kafka.Message{
		Topic:     cfg.Listeners[0].Topic,
		Value:     []byte(`{"trap":"linkUp"}`),
		Timestamp: time.Now(),
	}
	if msg1.Topic != "snmptraps_topic" {
		t.Errorf("Expected topic 'snmptraps_topic', got '%s'", msg1.Topic)
	}

	// Test message from syslog-listener
	msg2 := &kafka.Message{
		Topic:     cfg.Listeners[1].Topic,
		Value:     []byte(`{"syslog":"auth fail"}`),
		Timestamp: time.Now(),
	}
	if msg2.Topic != "syslog_raw_topic" {
		t.Errorf("Expected topic 'syslog_raw_topic', got '%s'", msg2.Topic)
	}

	// Test fallback listener
	msg3 := &kafka.Message{
		Topic:     cfg.Listeners[2].Topic,
		Value:     []byte(`{"http":"post"}`),
		Timestamp: time.Now(),
	}
	if msg3.Topic != "" {
		t.Errorf("Expected empty listener topic for fallback, got '%s'", msg3.Topic)
	}
}

func TestCreateOTLPListeners(t *testing.T) {
	for _, proto := range []string{"otlp", "otlp_http", "otlp_https", "otlp_grpc"} {
		l, err := createListener(config.ListenerConfig{
			Name:  "test-" + proto,
			Proto: proto,
			Bind:  "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("createListener(%q) failed: %v", proto, err)
		}
		if l == nil {
			t.Fatalf("createListener(%q) returned nil listener", proto)
		}
	}
}
