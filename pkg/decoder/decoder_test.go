package decoder

import (
	"encoding/json"
	"testing"

	"x2kafka/pkg/config"
)

func TestFormatPayloadWithDynamicEnrichment(t *testing.T) {
	d := NewDecoder()

	cfg := config.ListenerConfig{
		Mode:          "json",
		EnrichmentKey: "sensor_uuid",
		EnrichmentMap: map[string]map[string]interface{}{
			"uuid-1234": {
				"sensor_name":     "Building A Trap Sensor",
				"organization_id": 100,
			},
		},
		EnrichmentRules: []config.EnrichmentRule{
			{
				MatchKey:   "fromhost_ip",
				MatchValue: "10.1.33.158",
				Topic:      "rb_vault",
				Enrichment: map[string]interface{}{
					"sensor_name": "vaultD",
					"sensor_uuid": "a559d67c-b4f4-49a0-93a1-12df8f63341e",
				},
			},
			{
				MatchKey:   "fromhost_ip",
				MatchValue: "127.0.0.1",
				Contains:   []string{"ALERT", "RULE"},
				Topic:      "rb_vault",
				Enrichment: map[string]interface{}{
					"sensor_name": "CEP",
					"sensor_uuid": "8c125069-4c27-42a4-9a33-1f377385c485",
				},
			},
		},
	}

	// Test 1: Rule 1 match by IP
	raw1 := []byte(`{"raw_message":"<165>1 2026-09-26T12:00:00Z vaultD - - - - Test message"}`)
	out1, topic1, err := d.FormatPayloadWithConfigAndTopic(raw1, cfg, "syslog_udp", "10.1.33.158")
	if err != nil {
		t.Fatalf("FormatPayloadWithConfigAndTopic error: %v", err)
	}

	if topic1 != "rb_vault" {
		t.Errorf("Expected target topic 'rb_vault', got '%s'", topic1)
	}

	var p1 map[string]interface{}
	_ = json.Unmarshal(out1, &p1)
	if p1["sensor_name"] != "vaultD" {
		t.Errorf("Expected sensor_name 'vaultD', got '%v'", p1["sensor_name"])
	}

	// Test 2: Rule 2 match by IP + contains ALERT and RULE
	raw2 := []byte(`{"raw_message":"<165>1 2026-09-26T12:00:00Z cep - - - - ALERT: RULE triggered"}`)
	out2, topic2, err := d.FormatPayloadWithConfigAndTopic(raw2, cfg, "syslog_udp", "127.0.0.1")
	if err != nil {
		t.Fatalf("FormatPayloadWithConfigAndTopic error: %v", err)
	}

	if topic2 != "rb_vault" {
		t.Errorf("Expected target topic 'rb_vault', got '%s'", topic2)
	}

	var p2 map[string]interface{}
	_ = json.Unmarshal(out2, &p2)
	if p2["sensor_name"] != "CEP" {
		t.Errorf("Expected sensor_name 'CEP', got '%v'", p2["sensor_name"])
	}
}

func TestFormatPayloadWithParser(t *testing.T) {
	d := NewDecoder()

	cfg := config.ListenerConfig{
		Mode:                  "line",
		KVExtract:             true,
		CEFExtract:            true,
		SchemaStandardization: true,
		RegexPatterns: []string{
			`user=(?P<custom_user>\S+)`,
		},
	}

	raw := []byte(`CEF:0|Security|Firewall|1.0|100|Connection Denied|5|src=10.0.0.50 dst=192.168.1.1 spt=12345 dpt=80 proto=TCP user=admin`)
	out, _, err := d.FormatPayloadWithConfigAndTopic(raw, cfg, "syslog_udp", "192.168.10.1")
	if err != nil {
		t.Fatalf("Decoder error: %v", err)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if res["src_ip"] != "10.0.0.50" {
		t.Errorf("Expected src_ip=10.0.0.50, got %v", res["src_ip"])
	}
	if res["dst_ip"] != "192.168.1.1" {
		t.Errorf("Expected dst_ip=192.168.1.1, got %v", res["dst_ip"])
	}
	if res["src_port"] != float64(12345) { // JSON unmarshals ints to float64
		t.Errorf("Expected src_port=12345, got %v", res["src_port"])
	}
	if res["dst_port"] != float64(80) {
		t.Errorf("Expected dst_port=80, got %v", res["dst_port"])
	}
	if res["transport"] != "TCP" {
		t.Errorf("Expected transport=TCP, got %v", res["transport"])
	}
	if res["custom_user"] != "admin" {
		t.Errorf("Expected custom_user=admin, got %v", res["custom_user"])
	}
}


func TestFormatPayloadSkipsSensorHomeNets(t *testing.T) {
	d := NewDecoder()
	cfg := config.ListenerConfig{
		Mode:          "json",
		EnrichmentKey: "sensor_ip",
		EnrichmentMap: map[string]map[string]interface{}{
			"10.0.0.1": {
				"sensor_name": "sflow-sensor",
				"home_nets":   []interface{}{"192.168.0.0/16"},
			},
		},
	}

	out, _, err := d.FormatPayloadWithConfigAndTopic([]byte(`{"sensor_ip":"10.0.0.1","bytes":10}`), cfg, "sflow", "10.0.0.1")
	if err != nil {
		t.Fatalf("FormatPayloadWithConfigAndTopic error: %v", err)
	}
	var doc map[string]interface{}
	_ = json.Unmarshal(out, &doc)
	if doc["sensor_name"] != "sflow-sensor" {
		t.Errorf("expected sensor_name 'sflow-sensor', got '%v'", doc["sensor_name"])
	}
	if _, ok := doc["home_nets"]; ok {
		t.Errorf("home_nets must not be added to the event: %v", doc)
	}
}
