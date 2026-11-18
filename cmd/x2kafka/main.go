package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"x2kafka/pkg/config"
	"x2kafka/pkg/engine"
	"x2kafka/pkg/parser/flow"
)

var (
	version  = "1.0.0"
	revision = "dev"
)

func printHelp() {
	fmt.Printf("x2kafka v%s-%s - Multi-protocol Ingestion to Kafka\n", version, revision)
	fmt.Println("Usage: x2kafka [options] [config.json]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c, -config <file>     Path to JSON configuration file (default /etc/x2kafka/config.json)")
	fmt.Println("  -d, -debug             Enable verbose payload & publishing debug logging")
	fmt.Println("  -h, -help              Show this help message and exit")
	fmt.Println("  -i, -info              Show detailed configuration fields and listener capabilities")
	fmt.Println("  -stats                 Fetch and display live daemon statistics from IPC socket or HTTP endpoint")
	fmt.Println("  -v, -version           Show version and exit")
	fmt.Println()
	fmt.Println("Signals:")
	fmt.Println("  SIGHUP                 Reload configuration file gracefully without dropping connections")
	fmt.Println("  SIGINT, SIGTERM        Graceful daemon shutdown")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  x2kafka -c /etc/x2kafka/config.json")
	fmt.Println("  x2kafka -d /etc/x2kafka/config.json")
	fmt.Println("  x2kafka -stats")
	fmt.Println("  x2kafka -i")
}

func printInfo() {
	fmt.Printf("x2kafka v%s-%s - Architecture & Configuration Reference\n", version, revision)
	fmt.Println(strings.Repeat("=", 68))
	fmt.Println()
	fmt.Println("GLOBAL CONFIGURATION FIELDS:")
	fmt.Println("  brokers            (array|string): Kafka brokers (e.g. [\"kafka.service:9092\"])")
	fmt.Println("  topic              (string): Default fallback Kafka topic")
	fmt.Println("  client_id          (string): Kafka client identifier")
	fmt.Println("  async              (bool): Async Kafka delivery mode (high throughput)")
	fmt.Println("  batch_size         (int): Max messages per Kafka batch (default 500)")
	fmt.Println("  batch_timeout_ms   (int): Max wait time in ms before flushing Kafka batch")
	fmt.Println("  num_workers        (int): Parallel pipeline processing workers (default CPU*2)")
	fmt.Println("  channel_buffer_size(int): Internal queue depth (default 50000)")
	fmt.Println("  compression        (string): Kafka compression: \"none\", \"lz4\", \"gzip\", \"snappy\", \"zstd\"")
	fmt.Println("  socket_buffer_bytes(int): OS socket receive buffer in bytes (default 8MB)")
	fmt.Println("  allowed_ips        (array): Global allowed IP / CIDR list (e.g. [\"10.0.0.0/8\"])")
	fmt.Println("  blacklist_ips      (array): Global denied IP / CIDR list")
	fmt.Println("  stats_socket       (string): Unix domain socket path for IPC stats (default /run/x2kafka/x2kafka.sock)")
	fmt.Println("  stats_port         (int): HTTP port for /stats and /health endpoints (default 7979)")
	fmt.Println("  stats_bind         (string): Bind IP for HTTP stats (default 127.0.0.1)")
	fmt.Println("  mib_dirs           (array): Custom directory paths containing SNMP MIB files")
	fmt.Println()
	fmt.Println("LISTENER PROTOCOLS & CONFIGURATION (\"listeners\" array):")
	fmt.Println("  proto              (string): Listener protocol type:")
	fmt.Println("                       - \"syslog\": Listens on both UDP and TCP port simultaneously")
	fmt.Println("                       - \"syslog_udp\", \"syslog_tcp\": Standard RFC 5424 / RFC 3164 Syslog")
	fmt.Println("                       - \"syslog_unix\": Syslog over Unix stream or datagram socket")
	fmt.Println("                       - \"snmptrap\": Listens on UDP and TCP (port 162) with direct MIB resolution")
	fmt.Println("                       - \"http\", \"https\": REST API endpoint with auto gzip/zlib/deflate")
	fmt.Println("                       - \"unix\", \"fifo\": Raw or newline-delimited local stream/pipe")
	fmt.Println("  bind               (string): Bind IP address (e.g. \"0.0.0.0\")")
	fmt.Println("  port               (int): Network port (e.g. 514 for syslog, 162 for snmp, 7980 for http)")
	fmt.Println("  path               (string): Path for unix domain socket or fifo pipe")
	fmt.Println("  topic              (string): Topic override for this listener")
	fmt.Println("  mode               (string): \"line\", \"raw\", \"json\", or \"syslog\"")
	fmt.Println()
	fmt.Println("MESSAGE EXTRACTION & SCHEMA NORMALIZATION:")
	fmt.Println("  kv_extract         (bool): Auto-extract key=value or key=\"value\" pairs")
	fmt.Println("  cef_extract        (bool): Auto-extract Common Event Format (CEF) headers & extensions")
	fmt.Println("  regex_patterns     (array): Named regex capture groups, e.g. [\"user=(?P<user>\\\\S+)\"]")
	fmt.Println("  schema_standardization(bool): Normalize vendor keys to redBorder schema:")
	fmt.Println("                       src, srcip, source_ip       -> src_ip")
	fmt.Println("                       dst, dstip, destination_ip  -> dst_ip")
	fmt.Println("                       spt, srcport                -> src_port")
	fmt.Println("                       dpt, dstport                -> dst_port")
	fmt.Println("                       user, usr, suser            -> username")
	fmt.Println("                       proto, protocol             -> transport")
	fmt.Println()
	fmt.Println("DYNAMIC ENRICHMENT & ROUTING (\"enrichment_rules\"):")
	fmt.Println("  match_key / match_value: Match single payload or metadata field (e.g. src_ip: 10.1.33.158)")
	fmt.Println("  match_fields       (map): Multi-field AND matching, e.g. {\"src_ip\": \"127.0.0.1\", \"app_name\": \"sshd\"}")
	fmt.Println("  contains           (array): Substring match in raw payload (e.g. [\"ALERT\", \"RULE\"])")
	fmt.Println("  topic              (string): Target topic override when rule matches")
	fmt.Println("  enrichment         (map): Key-value fields injected into output JSON")
	fmt.Println()
}

func main() {
	var (
		configFile string
		debug      bool
		showStats  bool
		showVer    bool
		showHelp   bool
		showInfo   bool
	)

	// Support short and long flags
	flag.StringVar(&configFile, "c", "/etc/x2kafka/config.json", "Path to configuration file")
	flag.StringVar(&configFile, "config", "/etc/x2kafka/config.json", "Path to configuration file")
	flag.BoolVar(&debug, "d", false, "Enable verbose debug logging")
	flag.BoolVar(&debug, "debug", false, "Enable verbose debug logging")
	flag.BoolVar(&showStats, "stats", false, "Fetch and display live daemon stats from IPC socket or HTTP endpoint")
	flag.BoolVar(&showVer, "v", false, "Show version and exit")
	flag.BoolVar(&showVer, "version", false, "Show version and exit")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.BoolVar(&showInfo, "i", false, "Show detailed configuration fields and capabilities")
	flag.BoolVar(&showInfo, "info", false, "Show detailed configuration fields and capabilities")

	flag.Usage = printHelp
	flag.Parse()

	if showHelp {
		printHelp()
		os.Exit(0)
	}

	if showInfo {
		printInfo()
		os.Exit(0)
	}

	if showVer {
		fmt.Printf("x2kafka version %s (commit %s)\n", version, revision)
		_, ndpiInfo := flow.NDPIStatus()
		fmt.Printf("nDPI support: %s\n", ndpiInfo)
		os.Exit(0)
	}

	if len(flag.Args()) > 0 && configFile == "/etc/x2kafka/config.json" {
		configFile = flag.Arg(0)
	}

	log.Printf("Starting x2kafka v%s-%s with config: %s", version, revision, configFile)

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Fatal: Failed to load config: %v", err)
	}

	if showStats {
		fetchAndPrintStats(cfg)
		os.Exit(0)
	}

	if debug {
		cfg.Debug = true
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Fatal: Failed to initialize engine: %v", err)
	}

	if err := eng.Start(); err != nil {
		log.Fatalf("Fatal: Engine start failed: %v", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigs
		if sig == syscall.SIGHUP {
			log.Printf("SIGHUP received, reloading configuration from %s...", configFile)
			newCfg, err := config.LoadConfig(configFile)
			if err != nil {
				log.Printf("Reload failed: %v", err)
				continue
			}
			eng.Stop()
			newEng, err := engine.NewEngine(newCfg)
			if err != nil {
				log.Printf("Reload engine creation failed: %v", err)
				continue
			}
			eng = newEng
			if err := eng.Start(); err != nil {
				log.Printf("Reload engine start failed: %v", err)
			}
		} else {
			log.Printf("Signal %v received, shutting down gracefully...", sig)
			eng.Stop()
			break
		}
	}
}

func fetchAndPrintStats(cfg *config.Config) {
	// First try UNIX domain socket if socket file exists or is configured
	sockPath := cfg.StatsSocket
	if sockPath == "" {
		sockPath = config.DefaultSocketPath()
	}

	if conn, err := net.Dial("unix", sockPath); err == nil {
		defer conn.Close()
		_, _ = conn.Write([]byte("stats"))
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, conn); err == nil && buf.Len() > 0 {
			body := buf.Bytes()
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
				fmt.Println(prettyJSON.String())
				return
			}
			fmt.Println(string(body))
			return
		}
	}

	// Fallback to HTTP TCP query
	port := cfg.StatsPort
	if port <= 0 {
		port = 7979
	}
	bind := cfg.StatsBind
	if bind == "" || bind == "0.0.0.0" {
		bind = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s:%d/stats", bind, port)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying stats from socket (%s) or HTTP endpoint (%s): %v\n", sockPath, url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response from %s: %v\n", url, err)
		os.Exit(1)
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
		fmt.Println(prettyJSON.String())
	} else {
		fmt.Println(string(body))
	}
}
