# x2kafka & kafka2x

This repository provides two high-performance streaming daemons for the redBorder platform:

1. **`x2kafka`** (Ingress): Collects data events from UNIX domain sockets, named pipes (FIFOs), Syslog (UDP/TCP/UNIX), Direct SNMP Traps, and HTTP(S) endpoints into Apache Kafka topics.
2. **`kafka2x`** (Egress): Consumes events from Kafka topics and reliably forwards them in batches to remote HTTP(S) REST bulk endpoints with compression, framing, and automatic topic-qualified routing (replaces legacy `k2http` / `rbforwarder`).

---

## Key Features

### `x2kafka` (Ingress to Kafka)
- **Multi-Protocol Syslog Listener (`proto: "syslog"`, `"syslog_udp"`, `"syslog_tcp"`, `"syslog_unix"`)**: Parses RFC 3164 (BSD syslog) and RFC 5424 (IETF syslog) messages matching rsyslog schema fields. Specifying `"proto": "syslog"` automatically binds both UDP and TCP on the designated port.
- **HTTP / HTTPS & `http2k` Collector**:
  - **Transparent HTTP Decompression**: Automatically decompresses incoming GZIP, ZLIB, and raw DEFLATE payloads (supporting `kafka2x` / `k2http` compressed batches).
  - **Multi-Format Bulk Support**: Handles single JSON records, line-delimited records (NDJSON), JSON arrays (`[...]`), and concatenated JSON objects (`{...}{...}`).
  - **REST Path Routing & Sensor Extraction**: Parses REST URIs like `POST /rbdata/<sensor_uuid>/<topic>` (e.g., `POST /rbdata/bd2fe2c3-d0ff-4c27-aef9-122b698239b9/rb_flow`), extracting `sensor_uuid`, `proxy_uuid`, and the target Kafka topic dynamically.
- **UNIX Domain Sockets**: Supports both `unix` (Stream, SOCK_STREAM) and `unixgram` (Datagram, SOCK_DGRAM) sockets.
- **FIFO (Named Pipes)**: Continuously reads from Linux FIFOs with auto-reconnect handling for external writer processes.
- **Direct SNMP Trap Receiver**: Supports direct SNMP v1/v2c/v3 trap reception on UDP 162 (`snmptrap_udp`) with automatic numeric OID to MIB name translation using dynamic MIB directories (`mib_dirs`).
- **Standards-Compliant Flow Ingestion (`proto: "flow"`, `"netflow"`, `"ipfix"`, `"sflow"`)**:
  - **Multi-Version Auto-Detection**: Specifying `"proto": "netflow"` (or `"flow"`) on UDP 2055 automatically detects whether each incoming packet is NetFlow v5, v9, or IPFIX by inspecting the wire header. Devices sending different versions can share the same port.
  - **NetFlow v5 (RFC 1883)**: Fixed-format 5-tuple flow records (`type: "netflowv5"`).
  - **NetFlow v9 (RFC 3954)**: 100% dynamic template and options decoding (`type: "netflowv9"`).
  - **IPFIX / NetFlow v10 (RFC 7011 / 7012)**: Dynamic template decoding with variable-length elements and enterprise Information Elements (`type: "netflowv10"`).
  - **sFlow v5 (sFlow.org)**: Ingests Flow Samples (Format 1) and Expanded Flow Samples (Format 3) on UDP 6343 (`type: "sflow"`).
  - **100% Flat JSON Compatibility**: Drop-in replacement for `f2k` and `redborder-flow-agent`. Emits flat JSON records (no nested objects) for Druid/ClickHouse ingestion, with Cisco NBAR binary applications decoded into string `engine:app` identifiers (e.g. `"3:123"`).
  - **RedBorder Directional Model A (`home_nets`)**: Evaluates traffic orientation against configured `home_nets` CIDR blocks (defaults to RFC 1918/6598/4193). For downstream flows (WAN $\to$ LAN), `lan_ip` is automatically oriented to the internal host, with `direction` set to `"upstream"`, `"downstream"`, or `"internal"`.
  - **L7 & Network Layer Metadata**: Decodes HTTP User-Agent (`http_user_agent`), URL (`http_url`), Host (`http_host`), Referer (`http_referer`), human-readable TCP flags (`tcp_flags`, e.g. `"SYN|ACK"`), and TTL (`src_ttl`, `dst_ttl`) from Cisco AVC/NBAR2, IPFIX, and sFlow.
  - **Output Schema & `sensor_ip`**: Emits normalized flow JSON with `sensor_ip` automatically populated with the exporter's IP address, alongside `lan_ip`, `wan_ip`, `lan_l4_port`, `wan_l4_port`, `l4_proto`, `bytes`, `pkts`, and timestamps.
  - **Sampling Renormalization (`renormalize_sampling`)**: Automatically scales byte and packet volumes by the flow sampling rate so downstream metrics reflect true wire volume.
  - **SPAN Port Mode (`span_port`)**: Configurable per-listener boolean. When enabled (`"span_port": true`), ingress MAC addresses are prioritized over post-routed gateway MACs (`postDestinationMacAddress`), matching mirrored SPAN port tap behavior.
  - **Observation ID Enrichment (`observation_domain_id` / `observations_id`)**: Extracts NetFlow v9 Source ID and IPFIX Observation Domain ID into `observation_domain_id`. Supports hierarchical enrichment lookup matching both flat `<ip>:<observation_id>` keys and nested Chef `observations_id` maps.
  - **Field Exclusion (`exclude_fields`)**: Allows dropping specified flow fields from the emitted JSON records before Kafka serialization.
- **Native OpenTelemetry (OTLP) Receiver (`proto: "otlp"`, `"otlp_http"`, `"otlp_https"`, `"otlp_grpc"`)**:
  - **Dual Transport (`:4318` HTTP/S & `:4317` gRPC)**: Specifying `"proto": "otlp"` automatically starts both the OTLP/HTTP (`:4318`, supporting `application/x-protobuf` and `application/json` with GZIP/ZLIB/Deflate decompression) and OTLP/gRPC (`:4317`, supporting Protobuf and GZIP) receivers.
  - **Signal-Based Topic Routing & Per-Signal Enrichment**: Automatically distinguishes OpenTelemetry signals, enriches each signal with its dedicated sensor metadata (`metrics`, `logs`, `traces` sub-maps inside `enrichment_map`), and routes flattened JSON records to dedicated topics:
    - **Metrics** (`/v1/metrics` / `MetricsService`) $\to$ `rb_monitor` (configurable via `metrics_topic`; unpacks Gauge, Sum, Histogram, ExponentialHistogram, and Summary data points).
    - **Logs** (`/v1/logs` / `LogsService`) $\to$ `rb_vault` (configurable via `logs_topic`; supports KV/CEF/Regex extraction and schema standardization).
    - **Traces** (`/v1/traces` / `TraceService`) $\to$ optional (disabled by default unless `traces_topic` is set, e.g. `"rb_trace"`; emits flattened spans with `trace_id`, `span_id`, `parent_span_id`, `duration_ms`, and status).
  - **Automatic Resource & Attribute Flattening**: Merges OTel `resource.attributes` (mapping `host.name` to `hostname`), `scope` metadata, and signal attributes into flat top-level JSON keys with `sensor_ip` and `/rbdata/<sensor_uuid>/v1/...` path enrichment.
- **IP Security & Subnet Filtering**: Granular IP allowlisting (`allowed_ips`) and blacklisting (`blacklist_ips`) supporting single IPs and CIDR subnet blocks globally or per listener.
- **Message Splitting & Field Extraction**: Extract structured data from raw log strings using Key-Value parsing (`kv_extract`), CEF security headers (`cef_extract`), or custom named Regex patterns (`regex_patterns`).
- **Schema Standardization**: Map vendor-specific log keys (e.g., `src`, `srcip`, `source_ip`) to unified redBorder schema keys (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `transport`, `username`) automatically via `schema_standardization`.
- **Dynamic & Static JSON Enrichment**: Flexible per-sensor lookup maps (`enrichment_map`) and conditional rules engine (`contains`, `match_key`) for tagging JSON payloads.

### `kafka2x` (Egress from Kafka to HTTP/REST)
- **Consumer Group Engine**: Subscribes to multiple Kafka topics (e.g. `rb_flow`, `rb_monitor`, `rb_syslog`, `rb_trap`) with automatic partition rebalancing and fault tolerance.
- **Topic-Qualified URL Dispatch**: Automatically appends the source Kafka topic to the destination REST path (e.g., posting to `/rbdata/<sensor_uuid>` automatically dispatches batches to `/rbdata/<sensor_uuid>/rb_flow`, `/rbdata/<sensor_uuid>/rb_monitor`, etc.).
- **RFC-Compliant Compression**: Clean stream compression supporting `"gzip"`, `"zlib"`, `"deflate"`, or `"none"` (guarantees valid Adler-32 / CRC32 checksum footers).
- **Framing Modes**:
  - `"newline"`: Standard newline-delimited JSON (NDJSON / `\n`).
  - `"concatenated"`: RedBorder streaming concatenated JSON (`{...}{...}`).
  - `"json_array"`: Standard JSON array bulk (`[ {...}, {...} ]`).
- **At-Least-Once Delivery**: Kafka consumer offsets are only committed after a successful HTTP 2xx response from the remote endpoint. If the destination is temporarily unavailable, workers retry with configurable backoff.
- **HTTP Connection Pooling**: Tuned `http.Transport` with persistent connection reuse and TLS verification settings.

---

## IP Security & Access Control (`x2kafka`)

`x2kafka` supports granular IP address and CIDR subnet filtering to restrict data ingestion to authorized senders:

```json
{
  "brokers": ["127.0.0.1:9092"],
  "topic": "rb_trap",
  "allowed_ips": ["10.1.33.0/24", "192.168.10.1"],
  "blacklist_ips": ["10.1.33.100"],
  "listeners": [
    {
      "name": "snmptrap-listener",
      "proto": "snmptrap_udp",
      "port": 162,
      "allowed_ips": ["192.168.10.0/24"]
    }
  ]
}
```

---

## Configuration

### 1. `x2kafka` Ingress Config (`/etc/x2kafka/config.json`)

```json
{
  "debug": false,
  "brokers": ["kafka.service:9092"],
  "topic": "x2kafka_default",
  "num_workers": 16,
  "channel_buffer_size": 50000,
  "socket_buffer_bytes": 8388608,
  "stats_port": 7979,
  "stats_socket": "/run/x2kafka/x2kafka.sock",
  "listeners": [
    {
      "name": "syslog-collector",
      "proto": "syslog",
      "bind": "0.0.0.0",
      "port": 514,
      "mode": "syslog",
      "topic": "rb_syslog",
      "kv_extract": true,
      "cef_extract": true,
      "schema_standardization": true
    },
    {
      "name": "http2k-listener",
      "proto": "http",
      "bind": "0.0.0.0",
      "port": 7980,
      "mode": "json",
      "enrichment_key": "sensor_uuid",
      "enrichment_map": {
        "bd2fe2c3-d0ff-4c27-aef9-122b698239b9": {
          "index_partitions": 5,
          "index_replicas": 1,
          "proxy_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9",
          "sensor_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9"
        }
      }
    },
    {
      "name": "snmptrap-listener",
      "proto": "snmptrap",
      "bind": "0.0.0.0",
      "port": 162,
      "topic": "rb_trap"
    },
    {
      "name": "netflow-listener",
      "proto": "netflow",
      "bind": "0.0.0.0",
      "port": 2055,
      "topic": "rb_flow",
      "home_nets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      "renormalize_sampling": true,
      "span_port": false,
      "exclude_fields": ["tcp_flags", "duration"],
      "allowed_ips": ["10.0.0.0/8", "192.168.1.0/24"],
      "enrichment_key": "sensor_ip",
      "enrichment_map": {
        "10.10.10.1": {
          "observations_id": {
            "100": { "sensor_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9", "sensor_name": "router-subdomain-100" },
            "default": { "sensor_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9", "sensor_name": "router-default" }
          }
        }
      }
    },
    {
      "name": "sflow-listener",
      "proto": "sflow",
      "bind": "0.0.0.0",
      "port": 6343,
      "topic": "rb_flow",
      "home_nets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      "renormalize_sampling": true,
      "allowed_ips": ["10.0.0.0/8"],
      "enrichment_key": "sensor_ip",
      "enrichment_map": {
        "10.20.20.1": {
          "sensor_uuid": "e55fe2c3-d0ff-4c27-aef9-122b698239e5",
          "sensor_name": "switch-core-01"
        }
      }
    },
    {
      "name": "opentelemetry-grpc",
      "proto": "otlp_grpc",
      "bind": "0.0.0.0",
      "port": 4317,
      "metrics_topic": "rb_monitor",
      "logs_topic": "rb_vault",
      "kv_extract": true,
      "cef_extract": true,
      "schema_standardization": true,
      "allowed_ips": ["10.0.0.0/8", "192.168.0.0/16"],
      "enrichment_key": "sensor_ip",
      "enrichment_map": {
        "10.20.20.10": {
          "metrics": {
            "sensor_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9",
            "sensor_name": "snmp-monitor-01"
          },
          "logs": {
            "sensor_uuid": "e90902da-cec3-4020-9eaf-708ee32f86ac",
            "sensor_name": "vault-sensor-01"
          },
          "traces": {
            "sensor_uuid": "f11902da-cec3-4020-9eaf-708ee32f8699",
            "sensor_name": "trace-sensor-01"
          }
        }
      }
    },
    {
      "name": "opentelemetry-http",
      "proto": "otlp_http",
      "bind": "0.0.0.0",
      "port": 4318,
      "metrics_topic": "rb_monitor",
      "logs_topic": "rb_vault",
      "kv_extract": true,
      "cef_extract": true,
      "schema_standardization": true,
      "allowed_ips": ["10.0.0.0/8", "192.168.0.0/16"],
      "enrichment_key": "sensor_ip",
      "enrichment_map": {
        "10.20.20.10": {
          "metrics": {
            "sensor_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9",
            "sensor_name": "snmp-monitor-01"
          },
          "logs": {
            "sensor_uuid": "e90902da-cec3-4020-9eaf-708ee32f86ac",
            "sensor_name": "vault-sensor-01"
          },
          "traces": {
            "sensor_uuid": "f11902da-cec3-4020-9eaf-708ee32f8699",
            "sensor_name": "trace-sensor-01"
          }
        }
      }
    }
  ]
}
```

#### Emitted Flow JSON Schema (`rb_flow`)

100% flat JSON compatible with `f2k` and Druid/ClickHouse schemas:

```json
{
  "type": "netflowv10",
  "sensor_ip": "10.1.50.20",
  "flow_sequence": "57534",
  "ip_protocol_version": 4,
  "l4_proto": 17,
  "direction": "upstream",
  "application_id_name": "3:123",
  "engine_id_name": "3",
  "biflow_direction": "initiator",
  "flow_end_reason": "idle timeout",
  "lan_ip": "10.1.32.17",
  "wan_ip": "162.159.200.123",
  "lan_l4_port": 50024,
  "wan_l4_port": 123,
  "lan_interface": 13,
  "lan_interface_name": "13",
  "wan_interface": 1,
  "wan_interface_name": "1",
  "client_mac": "2c:f0:5d:0b:33:f0",
  "observation_domain_id": 100,
  "tcp_flags": "SYN|ACK",
  "src_ttl": 64,
  "dst_ttl": 58,
  "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) ...",
  "http_url": "https://example.com/api/v1",
  "http_host": "example.com",
  "bytes": 76,
  "pkts": 1,
  "timestamp": 1792523691
}
```
*Note: `"type"` is automatically set to `"netflowv5"`, `"netflowv9"`, `"netflowv10"` (IPFIX), or `"sflow"` based on the incoming datagram. Model A automatically ensures `"lan_ip"` is the internal `home_nets` IP and sets `"direction"` to `"upstream"` or `"downstream"`. HTTP metadata (`http_user_agent`, `http_url`, `http_host`) is decoded from Cisco AVC/NBAR2 or sFlow payloads when present.*

##### Flow Enrichment Resolution Order
When `enrichment_map` is configured on a flow listener:
1. `<exporter_ip>:<observation_id>` (e.g. `"10.1.50.20:100"`)
2. `<exporter_ip>` (or key defined by `enrichment_key`, e.g. `"10.1.50.20"`)
3. Nested Chef-style `observations_id` within the matched IP (`"10.1.50.20": { "observations_id": { "100": { ... }, "default": { ... } } }`)
4. `"default"` entry in `enrichment_map`

*If an exporter IP is defined directly without `observations_id` (e.g. `"10.1.50.20": { "sensor_uuid": "...", "sensor_name": "..." }`), it applies cleanly to all flows from that sensor IP without any special configuration needed.*

#### OpenTelemetry (`otlp`) Emitted Schemas & Client Configuration

When `"proto": "otlp"` is configured, `x2kafka` listens on both **HTTP (`:4318`)** and **gRPC (`:4317`)** (or individually via `"proto": "otlp_http"`, `"otlp_https"`, `"otlp_grpc"`).

##### Emitted Metric JSON (`rb_monitor`)
```json
{
  "type": "otel_metric",
  "timestamp": 1730000000,
  "timestamp_ns": 1730000000000000000,
  "sensor_ip": "10.20.20.10",
  "hostname": "web-prod-01",
  "host.name": "web-prod-01",
  "service.name": "checkout-api",
  "scope_name": "otelcol/hostmetrics",
  "metric_name": "system.cpu.utilization",
  "metric_type": "gauge",
  "metric_unit": "1",
  "value": 0.42,
  "cpu": "0",
  "state": "user",
  "sensor_uuid": "bd2fe2c3-d0ff-4c27-aef9-122b698239b9",
  "sensor_name": "snmp-monitor-01"
}
```

##### Emitted Log JSON (`rb_vault`)
```json
{
  "type": "otel_log",
  "timestamp": 1730000010,
  "timestamp_ns": 1730000010000000000,
  "sensor_ip": "10.20.20.10",
  "hostname": "fw-01",
  "service.name": "sshd",
  "severity": "WARN",
  "severity_number": 13,
  "message": "action=denied srcip=10.1.2.3 dstip=192.168.1.10 user=admin",
  "src_ip": "10.1.2.3",
  "dst_ip": "192.168.1.10",
  "username": "admin",
  "trace_id": "0102030405060708090a0b0c0d0e0f10",
  "span_id": "0102030405060708",
  "sensor_uuid": "e90902da-cec3-4020-9eaf-708ee32f86ac",
  "sensor_name": "vault-sensor-01"
}
```

##### Example Remote Agent Config (`/etc/otelcol-contrib/config.yaml`)
```yaml
receivers:
  hostmetrics:
    collection_interval: 30s
    scrapers:
      cpu: {}
      memory: {}
      disk: {}
      filesystem: {}
      load: {}
      network: {}
  filelog:
    include: [/var/log/messages, /var/log/syslog, /var/log/secure, /var/log/auth.log]
    start_at: end

processors:
  resourcedetection:
    detectors: [env, system]
  batch:
    timeout: 5s

exporters:
  otlp/x2kafka:
    endpoint: "<X2KAFKA_MANAGER_IP>:4317"
    tls:
      insecure: true

service:
  pipelines:
    metrics:
      receivers: [hostmetrics]
      processors: [resourcedetection, batch]
      exporters: [otlp/x2kafka]
    logs:
      receivers: [filelog]
      processors: [resourcedetection, batch]
      exporters: [otlp/x2kafka]
```

##### Securing OTLP (Native TLS vs. Nginx Reverse Proxy)

Both **OTLP/HTTP** and **OTLP/gRPC** can be secured using TLS 1.2/1.3 in two ways:

###### Option 1: Native TLS directly in `x2kafka` (No Nginx required)
Configure `tls_cert` and `tls_key` on the OTLP listeners (`otlp_grpc` on `:4317`, `otlp_http` / `otlp_https` on `:4318`, or `"proto": "otlp"` which automatically binds both `:4318` and `:4317`):
```json
{
  "name": "otel-ingest-grpc",
  "proto": "otlp_grpc",
  "bind": "0.0.0.0",
  "port": 4317,
  "tls_cert": "/etc/pki/tls/certs/server.crt",
  "tls_key": "/etc/pki/tls/private/server.key",
  "metrics_topic": "rb_monitor",
  "logs_topic": "rb_vault",
  "enrichment_key": "sensor_ip"
}
```

###### Option 2: Nginx Reverse Proxy (`proxy_pass` for HTTP & `grpc_pass` for gRPC)
Alternatively, bind `x2kafka` to loopback (`"bind": "127.0.0.1"`) and terminate TLS in Nginx. When `x2kafka` receives a connection from loopback (`127.0.0.1` / `::1`), it automatically reads `X-Real-IP` or `X-Forwarded-For` (HTTP headers and gRPC metadata) so that `sensor_ip`, `allowed_ips` / `blacklist_ips`, and `enrichment_map` resolve the real remote OTel agent IP:

```nginx
# OTLP/HTTP over HTTPS (port 4318)
server {
    listen 4318 ssl;
    ssl_certificate     /etc/pki/tls/certs/server.crt;
    ssl_certificate_key /etc/pki/tls/private/server.key;

    location / {
        proxy_pass http://127.0.0.1:4318;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

# OTLP/gRPC over TLS + HTTP/2 (port 4317)
server {
    listen 4317 ssl http2;
    ssl_certificate     /etc/pki/tls/certs/server.crt;
    ssl_certificate_key /etc/pki/tls/private/server.key;

    location / {
        grpc_pass grpc://127.0.0.1:4317;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

###### Remote Agent TLS Configuration (`/etc/otelcol-contrib/config.yaml`)
With either Option 1 or Option 2 enabled, update the exporter on the remote OTel Collector:
```yaml
exporters:
  otlp/x2kafka:
    endpoint: "<X2KAFKA_MANAGER_IP>:4317"
    tls:
      insecure: false
      ca_file: /etc/otelcol-contrib/certs/ca.crt
```


### 2. `kafka2x` Egress Config (`/etc/kafka2x/config.json`)

Supports both JSON and legacy YAML format:

```json
{
  "debug": false,
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
  "stats_port": 7989,
  "stats_socket": "/run/kafka2x/kafka2x.sock"
}
```

---

## CLI Usage & Monitoring

Both daemons offer CLI commands to query stats and run diagnostics:

### `x2kafka`
```bash
# Query live stats via UNIX socket or HTTP:
x2kafka -stats -c /etc/x2kafka/config.json

# Query stats directly with curl or netcat:
curl --unix-socket /run/x2kafka/x2kafka.sock http://localhost/stats
curl http://127.0.0.1:7979/stats
echo "stats" | nc -U /run/x2kafka/x2kafka.sock

# Run in debug mode:
x2kafka -d -c /etc/x2kafka/config.json
```

### `kafka2x`
```bash
# Query live stats via UNIX socket or HTTP:
kafka2x -stats -c /etc/kafka2x/config.json

# Query stats directly:
curl --unix-socket /run/kafka2x/kafka2x.sock http://localhost/stats
curl http://127.0.0.1:7989/stats
echo "stats" | nc -U /run/kafka2x/kafka2x.sock

# Run in debug mode:
kafka2x -d -c /etc/kafka2x/config.json
```

---

## Build & Test

Build both binaries into `bin/`:
```bash
make build
```

Run test suite across all packages:
```bash
make test
```

Code linting and vetting:
```bash
make lint
```

---

## Packaging (Separate RPMs)

Building the RPM produces two distinct packages:
1. `x2kafka-<version>-<release>.x86_64.rpm` (Daemon binary `/usr/bin/x2kafka`, `/etc/x2kafka/config.json`, `x2kafka.service`)
2. `kafka2x-<version>-<release>.x86_64.rpm` (Daemon binary `/usr/bin/kafka2x`, `/etc/kafka2x/config.json`, `kafka2x.service`)

Build packages using mock:
```bash
make rpm
```

---

## Systemd Service Management

Each daemon has its own isolated systemd service:

### Start & Enable `x2kafka`
```bash
sudo systemctl enable --now x2kafka
sudo systemctl status x2kafka
```

### Start & Enable `kafka2x`
```bash
sudo systemctl enable --now kafka2x
sudo systemctl status kafka2x
```

---

## Production Best Practice: Dedicated Services per Protocol

While `x2kafka` can run all listeners inside a single process, the **recommended production architecture** is to run dedicated systemd services for each protocol (`syslog`, `http2k`, `snmptrap`).

### Why Separate Services?
1. **Isolated Fault Domains**: A spike in Syslog traffic or a slow network client won't affect HTTP2K or SNMP Trap ingestion.
2. **Independent Restarts & Upgrades**: Restarting or reloading one collector (e.g. `systemctl restart x2kafka-syslog`) does not interrupt connections to other endpoints.
3. **Dedicated Tuning & Resource Limits**: Allows assigning custom CPU quotas, worker thread counts, memory limits (`MemoryMax=`), or scheduling priorities per service in systemd.
4. **Independent Monitoring**: Each service runs with its own telemetry port and IPC socket, allowing independent throughput and error tracking.

### Example Service Files & Configurations

Example systemd units and configs are provided in the repository:
- **Syslog Service (UDP/TCP 514)**:
  - Unit: [`resources/systemd/examples/x2kafka-syslog.service`](resources/systemd/examples/x2kafka-syslog.service)
  - Config: [`configs_example/x2kafka_syslog.json`](configs_example/x2kafka_syslog.json) (`stats_port: 7979`, `stats_socket: /run/x2kafka/syslog.sock`)
- **HTTP2K Service (HTTP 7980)**:
  - Unit: [`resources/systemd/examples/x2kafka-http2k.service`](resources/systemd/examples/x2kafka-http2k.service)
  - Config: [`configs_example/x2kafka_http2k.json`](configs_example/x2kafka_http2k.json) (`stats_port: 7980`, `stats_socket: /run/x2kafka/http2k.sock`)
- **Direct SNMP Trap Receiver (UDP 162)**:
  - Unit: [`resources/systemd/examples/x2kafka-snmptrap.service`](resources/systemd/examples/x2kafka-snmptrap.service)
  - Config: [`configs_example/x2kafka_snmptrap.json`](configs_example/x2kafka_snmptrap.json) (`stats_port: 7981`, `stats_socket: /run/x2kafka/snmptrap.sock`)
- **NetFlow / IPFIX / sFlow Receiver (UDP 2055 & 6343)**:
  - Config: [`configs_example/x2kafka_flow.json`](configs_example/x2kafka_flow.json)
- **OpenTelemetry (OTLP) Receiver (gRPC 4317 & HTTP 4318)**:
  - Config: [`configs_example/x2kafka_otlp.json`](configs_example/x2kafka_otlp.json)

### How to Deploy Dedicated Services:

```bash
# 1. Copy the configuration files to /etc/x2kafka/
sudo cp configs_example/x2kafka_syslog.json /etc/x2kafka/syslog.json
sudo cp configs_example/x2kafka_http2k.json /etc/x2kafka/http2k.json
sudo cp configs_example/x2kafka_snmptrap.json /etc/x2kafka/snmptrap.json

# 2. Copy the example systemd unit files to /etc/systemd/system/
sudo cp resources/systemd/examples/x2kafka-syslog.service /etc/systemd/system/
sudo cp resources/systemd/examples/x2kafka-http2k.service /etc/systemd/system/
sudo cp resources/systemd/examples/x2kafka-snmptrap.service /etc/systemd/system/

# 3. Reload systemd and enable the services you require
sudo systemctl daemon-reload
sudo systemctl enable --now x2kafka-syslog
sudo systemctl enable --now x2kafka-http2k
sudo systemctl enable --now x2kafka-snmptrap
```

> [!IMPORTANT]
> When running multiple `x2kafka` instances concurrently on the same host, ensure that each configuration specifies a unique `stats_port` and `stats_socket` (as pre-configured in the example files) to prevent IPC socket or TCP port collisions.


