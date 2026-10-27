package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type Config struct {
	Debug             bool             `json:"debug,omitempty"`               // Verbose debug logging for payload processing & Kafka publishing
	Brokers           []string         `json:"-"`
	BrokersRaw        interface{}      `json:"brokers"`
	Topic             string           `json:"topic"`
	ClientID          string           `json:"client_id,omitempty"`
	Async             bool             `json:"async"`
	BatchSize         int              `json:"batch_size,omitempty"`
	BatchTimeoutMS    int              `json:"batch_timeout_ms,omitempty"`
	NumWorkers        int              `json:"num_workers,omitempty"`          // Number of parallel processing workers (default runtime.NumCPU() * 2)
	ChannelBufferSize int              `json:"channel_buffer_size,omitempty"`  // In-memory queue depth (default 50000)
	Compression       string           `json:"compression,omitempty"`          // Kafka compression: "lz4", "gzip", "snappy", "none"
	SocketBufferBytes int              `json:"socket_buffer_bytes,omitempty"`  // OS Socket receive buffer size (default 8MB)
	AllowedIPs        []string         `json:"allowed_ips,omitempty"`          // Global IP allowlist / CIDR blocks (e.g. ["10.1.33.0/24", "192.168.10.1"])
	BlacklistIPs      []string         `json:"blacklist_ips,omitempty"`        // Global IP blacklist / CIDR blocks (e.g. ["192.168.101.3"])
	HomeNets          []string         `json:"home_nets,omitempty"`            // Global home networks CIDRs (e.g. ["10.0.0.0/8", "192.168.0.0/16"])
	HomeNet           []string         `json:"home_net,omitempty"`             // Alias for home_nets
	StatsPort         int              `json:"stats_port,omitempty"`           // HTTP port for /stats endpoint
	StatsBind         string           `json:"stats_bind,omitempty"`           // Bind IP for stats endpoint
	StatsSocket       string           `json:"stats_socket,omitempty"`         // UNIX socket path for stats query (e.g. /run/x2kafka/x2kafka.sock)
	MibDirs           []string         `json:"mib_dirs,omitempty"`             // Paths containing SNMP MIB files
	ApplicationsFile  string           `json:"applications_file,omitempty"`     // Path to redBorder applications mapping file
	HostsPath         string           `json:"hosts_path,omitempty"`            // Path to redBorder objects directory (e.g. /etc/objects)
	Listeners         []ListenerConfig `json:"listeners"`
	RDKafkaOptions    map[string]string`json:"rdkafka_options,omitempty"`
}

// DefaultSocketPath checks system runtime directories and falls back to /run/x2kafka/x2kafka.sock or /tmp/x2kafka.sock
func DefaultSocketPath() string {
	runDir := "/run/x2kafka"
	if fi, err := os.Stat(runDir); err == nil && fi.IsDir() {
		testFile := fmt.Sprintf("%s/.test_write", runDir)
		if f, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666); err == nil {
			f.Close()
			_ = os.Remove(testFile)
			return "/run/x2kafka/x2kafka.sock"
		}
	}
	return "/tmp/x2kafka.sock"
}

type EnrichmentRule struct {
	MatchFields map[string]string     `json:"match_fields,omitempty"` // multi-field match map (e.g., {"fromhost_ip": "127.0.0.1", "app_name": "cep"})
	MatchKey    string                `json:"match_key,omitempty"`    // optional single key to check
	MatchValue  string                `json:"match_value,omitempty"`  // exact single value to match
	Contains    []string              `json:"contains,omitempty"`     // substring filters (e.g., ["ALERT", "RULE"])
	Topic       string                `json:"topic,omitempty"`        // target topic override if matched
	Enrichment  map[string]interface{} `json:"enrichment"`             // metadata fields to add if matched
}

type ListenerConfig struct {
	Name            string                            `json:"name,omitempty"`
	Proto           string                            `json:"proto"`            // "unix", "unixgram", "fifo", "syslog_udp", "syslog_tcp", "syslog_unix", "snmptrap_udp", "http", "https"
	Path            string                            `json:"path,omitempty"`     // for unix/fifo
	Bind            string                            `json:"bind,omitempty"`     // for udp/tcp/http
	Port            int                               `json:"port,omitempty"`     // for udp/tcp/http
	Topic           string                            `json:"topic,omitempty"`    // override topic
	Mode            string                            `json:"mode,omitempty"`     // "line", "raw", "json", "syslog"
	TLSCert         string                            `json:"tls_cert,omitempty"`
	TLSKey          string                            `json:"tls_key,omitempty"`
	AllowedIPs      []string                          `json:"allowed_ips,omitempty"`       // Per-listener IP allowlist / CIDR blocks
	BlacklistIPs    []string                          `json:"blacklist_ips,omitempty"`     // Per-listener IP blacklist / CIDR blocks
	Enrichment      map[string]interface{}            `json:"enrichment,omitempty"`        // default static enrichment
	EnrichmentKey   string                            `json:"enrichment_key,omitempty"`    // key to extract from record (e.g., "sensor_uuid", "hostname", "fromhost_ip")
	EnrichmentMap   map[string]map[string]interface{} `json:"enrichment_map,omitempty"`    // map[match_value]enrichment_fields
	EnrichmentRules []EnrichmentRule                  `json:"enrichment_rules,omitempty"`  // list of dynamic enrichment rules
	KVExtract            bool                              `json:"kv_extract,omitempty"`            // Auto-extract key=value pairs from string messages
	CEFExtract           bool                              `json:"cef_extract,omitempty"`           // Auto-extract CEF fields
	SchemaStandardization bool                             `json:"schema_standardization,omitempty"`// Normalize keys (src/srcip -> src_ip, etc.)
	RegexPatterns        []string                          `json:"regex_patterns,omitempty"`        // Named regex extraction patterns
	MaxMsgSize           int                               `json:"max_msg_size,omitempty"`
	SocketBufferBytes    int                               `json:"socket_buffer_bytes,omitempty"`
	ExcludeFields        []string                          `json:"exclude_fields,omitempty"`        // Flow fields to omit from JSON output
	TemplateTTLSeconds   int                               `json:"template_ttl_seconds,omitempty"`  // NetFlow/IPFIX template expiration in seconds
	RenormalizeSampling  *bool                             `json:"renormalize_sampling,omitempty"`  // Renormalize sFlow/NetFlow counters by sampling rate
	HomeNets             []string                          `json:"home_nets,omitempty"`             // Home network CIDRs for LAN/WAN orientation
	HomeNet              []string                          `json:"home_net,omitempty"`              // Alias for home_nets
	SpanPort             bool                              `json:"span_port,omitempty"`             // Mirror/SPAN port mode (prefers ingress MACs)
	ApplicationsFile     string                            `json:"applications_file,omitempty"`     // Path to redBorder applications mapping file
	HostsPath            string                            `json:"hosts_path,omitempty"`            // Path to redBorder objects directory (e.g. /etc/objects)
}

// LoadConfig reads and parses a JSON config file.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{
		Topic:             "x2kafka_default",
		ClientID:          "x2kafka",
		Async:             true,
		BatchSize:         500,
		BatchTimeoutMS:    10,
		NumWorkers:        runtime.NumCPU() * 2,
		ChannelBufferSize: 50000,
		SocketBufferBytes: 8 * 1024 * 1024,
		Compression:       "none",
	}

	if cfg.NumWorkers < 4 {
		cfg.NumWorkers = 4
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config json: %w", err)
	}

	switch b := cfg.BrokersRaw.(type) {
	case string:
		cfg.Brokers = []string{b}
	case []interface{}:
		for _, item := range b {
			if str, ok := item.(string); ok {
				cfg.Brokers = append(cfg.Brokers, str)
			}
		}
	default:
		cfg.Brokers = []string{"localhost:9092"}
	}

	if len(cfg.Brokers) == 0 {
		cfg.Brokers = []string{"localhost:9092"}
	}

	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = runtime.NumCPU() * 2
	}
	if cfg.ChannelBufferSize <= 0 {
		cfg.ChannelBufferSize = 50000
	}
	if cfg.SocketBufferBytes <= 0 {
		cfg.SocketBufferBytes = 8 * 1024 * 1024
	}
	if cfg.StatsSocket == "" {
		cfg.StatsSocket = DefaultSocketPath()
	}

	var expandedListeners []ListenerConfig
	for _, l := range cfg.Listeners {
		if l.Mode == "" {
			l.Mode = "line"
		}
		if l.MaxMsgSize <= 0 {
			l.MaxMsgSize = 65536
		}
		if l.EnrichmentKey == "" {
			l.EnrichmentKey = "sensor_uuid"
		}
		if l.SocketBufferBytes <= 0 {
			l.SocketBufferBytes = cfg.SocketBufferBytes
		}
		// Inherit global allowed/blacklist IPs if listener does not override
		if len(l.AllowedIPs) == 0 && len(cfg.AllowedIPs) > 0 {
			l.AllowedIPs = cfg.AllowedIPs
		}
		if len(l.BlacklistIPs) == 0 && len(cfg.BlacklistIPs) > 0 {
			l.BlacklistIPs = cfg.BlacklistIPs
		}
		// Inherit global home_nets if listener does not override
		if len(l.HomeNets) == 0 && len(l.HomeNet) > 0 {
			l.HomeNets = l.HomeNet
		}
		if len(l.HomeNets) == 0 {
			if len(cfg.HomeNets) > 0 {
				l.HomeNets = cfg.HomeNets
			} else if len(cfg.HomeNet) > 0 {
				l.HomeNets = cfg.HomeNet
			}
		}
		if l.ApplicationsFile == "" && cfg.ApplicationsFile != "" {
			l.ApplicationsFile = cfg.ApplicationsFile
		}
		if l.HostsPath == "" && cfg.HostsPath != "" {
			l.HostsPath = cfg.HostsPath
		}

		// Set default ports and topics for flow protocols if unset
		switch l.Proto {
		case "flow", "netflow", "netflow_udp", "ipfix":
			if l.Port == 0 {
				l.Port = 2055
			}
			if l.Topic == "" {
				l.Topic = "rb_flow"
			}
		case "sflow", "sflow_udp":
			if l.Port == 0 {
				l.Port = 6343
			}
			if l.Topic == "" {
				l.Topic = "rb_flow"
			}
		}

		// Support "syslog" (UDP + TCP), "snmptrap" (UDP + TCP), or comma-separated protos (e.g. "syslog_udp,syslog_tcp")
		if l.Proto == "syslog" {
			udpL := l
			udpL.Name = l.Name + "-udp"
			udpL.Proto = "syslog_udp"

			tcpL := l
			tcpL.Name = l.Name + "-tcp"
			tcpL.Proto = "syslog_tcp"

			expandedListeners = append(expandedListeners, udpL, tcpL)
		} else if l.Proto == "snmptrap" {
			udpL := l
			udpL.Name = l.Name + "-udp"
			udpL.Proto = "snmptrap_udp"

			tcpL := l
			tcpL.Name = l.Name + "-tcp"
			tcpL.Proto = "snmptrap_tcp"

			expandedListeners = append(expandedListeners, udpL, tcpL)
		} else if strings.Contains(l.Proto, ",") {
			protos := strings.Split(l.Proto, ",")
			for _, p := range protos {
				pTrim := strings.TrimSpace(p)
				if pTrim == "" {
					continue
				}
				subL := l
				subL.Name = l.Name + "-" + pTrim
				subL.Proto = pTrim
				expandedListeners = append(expandedListeners, subL)
			}
		} else {
			expandedListeners = append(expandedListeners, l)
		}
	}
	cfg.Listeners = expandedListeners

	return cfg, nil
}
