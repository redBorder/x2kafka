package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	content := `{
		"brokers": ["127.0.0.1:9092"],
		"topic": "test_topic",
		"listeners": [
			{
				"name": "test_fifo",
				"proto": "fifo",
				"path": "/tmp/test.fifo"
			}
		]
	}`

	tmpfile, err := os.CreateTemp("", "config_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpfile.Close()

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.Topic != "test_topic" {
		t.Errorf("Expected topic 'test_topic', got '%s'", cfg.Topic)
	}

	if len(cfg.Brokers) != 1 || cfg.Brokers[0] != "127.0.0.1:9092" {
		t.Errorf("Expected brokers ['127.0.0.1:9092'], got %v", cfg.Brokers)
	}

	if len(cfg.Listeners) != 1 {
		t.Fatalf("Expected 1 listener, got %d", len(cfg.Listeners))
	}

	if cfg.Listeners[0].Name != "test_fifo" {
		t.Errorf("Expected listener name 'test_fifo', got '%s'", cfg.Listeners[0].Name)
	}

	for _, path := range []string{
		"../../configs_example/x2kafka_syslog.json",
		"../../configs_example/x2kafka_http2k.json",
		"../../configs_example/x2kafka_snmptrap.json",
		"../../configs_example/x2kafka_flow.json",
		"../../configs_example/x2kafka_otlp.json",
	} {
		mCfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("Failed to load modular config %s: %v", path, err)
		}
		if len(mCfg.Listeners) == 0 {
			t.Errorf("Expected at least 1 listener in %s", path)
		}
	}
}

func TestLoadConfig_HomeNetsInheritance(t *testing.T) {
	content := `{
		"home_nets": ["10.0.0.0/8", "192.168.0.0/16"],
		"listeners": [
			{
				"name": "inherit_flow",
				"proto": "netflow"
			},
			{
				"name": "override_flow",
				"proto": "sflow",
				"home_nets": ["172.16.0.0/12"]
			}
		]
	}`

	tmpfile, err := os.CreateTemp("", "config_homenet_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpfile.Close()

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.Listeners[0].HomeNets) != 2 || cfg.Listeners[0].HomeNets[0] != "10.0.0.0/8" {
		t.Errorf("Expected inherited home_nets, got %v", cfg.Listeners[0].HomeNets)
	}
	if len(cfg.Listeners[1].HomeNets) != 1 || cfg.Listeners[1].HomeNets[0] != "172.16.0.0/12" {
		t.Errorf("Expected overridden home_nets, got %v", cfg.Listeners[1].HomeNets)
	}
}

func TestLoadConfig_OTLPExpansion(t *testing.T) {
	content := `{
		"brokers": ["127.0.0.1:9092"],
		"listeners": [
			{
				"name": "otel-collector",
				"proto": "otlp",
				"bind": "0.0.0.0"
			},
			{
				"name": "otel-custom-http",
				"proto": "otlp_http",
				"port": 14318,
				"metrics_topic": "custom_metrics",
				"logs_topic": "custom_logs",
				"traces_topic": "custom_traces"
			}
		]
	}`

	tmpfile, err := os.CreateTemp("", "config_otlp_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpfile.Close()

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.Listeners) != 3 {
		t.Fatalf("Expected 3 expanded listeners (otlp_http, otlp_grpc, otel-custom-http), got %d", len(cfg.Listeners))
	}

	httpL := cfg.Listeners[0]
	if httpL.Name != "otel-collector-http" || httpL.Proto != "otlp_http" || httpL.Port != 4318 {
		t.Errorf("Expected otel-collector-http on port 4318, got name=%q proto=%q port=%d", httpL.Name, httpL.Proto, httpL.Port)
	}
	if httpL.MetricsTopic != "rb_monitor" || httpL.LogsTopic != "rb_syslog" || httpL.TracesTopic != "rb_trace" {
		t.Errorf("Unexpected default signal topics: metrics=%q logs=%q traces=%q", httpL.MetricsTopic, httpL.LogsTopic, httpL.TracesTopic)
	}
	if httpL.MaxMsgSize != 4*1024*1024 {
		t.Errorf("Expected default OTLP MaxMsgSize 4MB, got %d", httpL.MaxMsgSize)
	}

	grpcL := cfg.Listeners[1]
	if grpcL.Name != "otel-collector-grpc" || grpcL.Proto != "otlp_grpc" || grpcL.Port != 4317 {
		t.Errorf("Expected otel-collector-grpc on port 4317, got name=%q proto=%q port=%d", grpcL.Name, grpcL.Proto, grpcL.Port)
	}
	if grpcL.MetricsTopic != "rb_monitor" || grpcL.LogsTopic != "rb_syslog" || grpcL.TracesTopic != "rb_trace" {
		t.Errorf("Unexpected default signal topics on gRPC: metrics=%q logs=%q traces=%q", grpcL.MetricsTopic, grpcL.LogsTopic, grpcL.TracesTopic)
	}

	customL := cfg.Listeners[2]
	if customL.Proto != "otlp_http" || customL.Port != 14318 {
		t.Errorf("Expected custom otlp_http on port 14318, got proto=%q port=%d", customL.Proto, customL.Port)
	}
	if customL.MetricsTopic != "custom_metrics" || customL.LogsTopic != "custom_logs" || customL.TracesTopic != "custom_traces" {
		t.Errorf("Expected custom signal topics, got metrics=%q logs=%q traces=%q", customL.MetricsTopic, customL.LogsTopic, customL.TracesTopic)
	}
}

func TestLoadEgressConfig(t *testing.T) {
	for _, filename := range []string{"../../configs_example/kafka2x_config.json", "../../configs_example/kafka2x_config.yaml"} {
		cfg, err := LoadEgressConfig(filename)
		if err != nil {
			t.Fatalf("LoadEgressConfig(%s) returned error: %v", filename, err)
		}
		if cfg.HTTP.URL == "" {
			t.Errorf("Expected non-empty HTTP URL for %s", filename)
		}
	}

	userConfig := `{
  "debug": true,
  "kafka": {
    "brokers": ["kafka.service:9092"],
    "group_id": "kafka2x-http-forwarder",
    "topics": [
      "rb_flow",
      "rb_monitor",
      "rb_syslog",
      "rb_trap"
    ]
  },
  "pipeline": {
    "workers": 2,
    "batch_size": 1000,
    "timeout_ms": 100,
    "retries": 3,
    "backoff_sec": 2
  },
  "http": {
    "url": "https://http2k.redborder.cluster/rbdata/938c7905-807e-4b8f-b488-70d525ac933b",
    "method": "POST",
    "framing": "newline",
    "compression": "gzip",
    "insecure": false,
    "timeout": "15s"
  },
  "stats_socket": "/run/x2kafka/kafka2x.sock"
}`

	tmpfile, err := os.CreateTemp("", "user_kafka2x_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	_, _ = tmpfile.Write([]byte(userConfig))
	tmpfile.Close()

	cfg, err := LoadEgressConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to parse user config: %v", err)
	}
	if !cfg.Debug {
		t.Errorf("Expected debug=true")
	}
	if cfg.HTTP.Timeout != "15s" {
		t.Errorf("Expected timeout '15s', got %q", cfg.HTTP.Timeout)
	}
}

