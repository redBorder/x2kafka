package listener

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"x2kafka/pkg/config"
	"x2kafka/pkg/kafka"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func strKV(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
	}
}

func intKV(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}},
	}
}

func TestOTLPHTTP_MetricsProtobufAndJSON(t *testing.T) {
	port := getFreePort(t)
	cfg := config.ListenerConfig{
		Name:         "test-otlp-http",
		Proto:        "otlp_http",
		Bind:         "127.0.0.1",
		Port:         port,
		MetricsTopic: "rb_monitor",
		LogsTopic:    "rb_syslog",
		TracesTopic:  "rb_trace",
		MaxMsgSize:   4 * 1024 * 1024,
		EnrichmentMap: map[string]map[string]interface{}{
			"sensor-123": {
				"sensor_name": "edge-otel-01",
			},
		},
		ExcludeFields: []string{"drop_me"},
	}

	l := NewOTLPListener(cfg)
	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	minVal := 1.5
	maxVal := 9.5
	sumVal := 15.0
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			{
				Resource: &resourcepb.Resource{
					Attributes: []*commonpb.KeyValue{
						strKV("host.name", "web-prod-01"),
						strKV("service.name", "checkout-api"),
						strKV("drop_me", "should-be-excluded"),
					},
				},
				ScopeMetrics: []*metricspb.ScopeMetrics{
					{
						Scope: &commonpb.InstrumentationScope{
							Name:    "otelcol/hostmetrics",
							Version: "0.110.0",
						},
						Metrics: []*metricspb.Metric{
							{
								Name: "system.cpu.utilization",
								Unit: "1",
								Data: &metricspb.Metric_Gauge{
									Gauge: &metricspb.Gauge{
										DataPoints: []*metricspb.NumberDataPoint{
											{
												TimeUnixNano: 1730000000000000000,
												Attributes:   []*commonpb.KeyValue{strKV("cpu", "0"), strKV("state", "user")},
												Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 0.42},
											},
										},
									},
								},
							},
							{
								Name: "http.server.duration",
								Unit: "ms",
								Data: &metricspb.Metric_Histogram{
									Histogram: &metricspb.Histogram{
										DataPoints: []*metricspb.HistogramDataPoint{
											{
												TimeUnixNano: 1730000005000000000,
												Count:        3,
												Sum:          &sumVal,
												Min:          &minVal,
												Max:          &maxVal,
												Attributes:   []*commonpb.KeyValue{intKV("http.status_code", 200)},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// 1. Send GZIP-compressed Protobuf to /rbdata/sensor-123/v1/metrics
	pbBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write(pbBytes)
	_ = gz.Close()

	url := fmt.Sprintf("http://127.0.0.1:%d/rbdata/sensor-123/v1/metrics", port)
	httpReq, _ := http.NewRequest(http.MethodPost, url, &gzBuf)
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("POST /v1/metrics failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	// Verify 2 flattened metric records arrived on rb_monitor
	for i := 0; i < 2; i++ {
		select {
		case msg := <-msgChan:
			if msg.Topic != "rb_monitor" {
				t.Errorf("Expected topic rb_monitor, got %q", msg.Topic)
			}
			var doc map[string]interface{}
			if err := json.Unmarshal(msg.Value, &doc); err != nil {
				t.Fatalf("Invalid JSON on msgChan: %v", err)
			}
			if doc["type"] != "otel_metric" {
				t.Errorf("Expected type=otel_metric, got %v", doc["type"])
			}
			if doc["hostname"] != "web-prod-01" || doc["host.name"] != "web-prod-01" {
				t.Errorf("Expected hostname=web-prod-01, got %v", doc["hostname"])
			}
			if doc["sensor_uuid"] != "sensor-123" || doc["sensor_name"] != "edge-otel-01" {
				t.Errorf("Expected enrichment sensor_uuid=sensor-123, sensor_name=edge-otel-01, got %v / %v", doc["sensor_uuid"], doc["sensor_name"])
			}
			if doc["sensor_ip"] != "127.0.0.1" {
				t.Errorf("Expected sensor_ip=127.0.0.1, got %v", doc["sensor_ip"])
			}
			if _, exists := doc["drop_me"]; exists {
				t.Errorf("Expected drop_me to be excluded")
			}
			if i == 0 {
				if doc["metric_name"] != "system.cpu.utilization" || doc["metric_type"] != "gauge" || doc["value"] != 0.42 {
					t.Errorf("Unexpected gauge record: %+v", doc)
				}
			} else {
				if doc["metric_name"] != "http.server.duration" || doc["metric_type"] != "histogram" || doc["count"] != float64(3) || doc["sum"] != 15.0 {
					t.Errorf("Unexpected histogram record: %+v", doc)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Timed out waiting for metric message %d", i)
		}
	}

	// 2. Also test application/json OTLP payload
	jsonBytes, err := protojson.Marshal(req)
	if err != nil {
		t.Fatalf("protojson.Marshal failed: %v", err)
	}
	jsonResp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/metrics", port), "application/json", bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("POST JSON /v1/metrics failed: %v", err)
	}
	defer jsonResp.Body.Close()
	if jsonResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for JSON OTLP, got %d", jsonResp.StatusCode)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-msgChan:
		case <-time.After(2 * time.Second):
			t.Fatalf("Timed out waiting for JSON metric message %d", i)
		}
	}
}

func TestOTLPHTTP_LogsAndTraces(t *testing.T) {
	port := getFreePort(t)
	cfg := config.ListenerConfig{
		Name:                  "test-otlp-logs-traces",
		Proto:                 "otlp_http",
		Bind:                  "127.0.0.1",
		Port:                  port,
		MetricsTopic:          "rb_monitor",
		LogsTopic:             "rb_syslog",
		TracesTopic:           "rb_trace",
		KVExtract:             true,
		SchemaStandardization: true,
		MaxMsgSize:            4 * 1024 * 1024,
	}

	l := NewOTLPListener(cfg)
	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	// 1. Send OTLP Logs request with KV pairs in body
	logsReq := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{
			{
				Resource: &resourcepb.Resource{
					Attributes: []*commonpb.KeyValue{
						strKV("host.name", "fw-01"),
						strKV("service.name", "sshd"),
					},
				},
				ScopeLogs: []*logspb.ScopeLogs{
					{
						LogRecords: []*logspb.LogRecord{
							{
								TimeUnixNano:   1730000010000000000,
								SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_WARN,
								SeverityText:   "WARN",
								Body: &commonpb.AnyValue{
									Value: &commonpb.AnyValue_StringValue{
										StringValue: "action=denied srcip=10.1.2.3 dstip=192.168.1.10 user=admin",
									},
								},
								TraceId:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Attributes: []*commonpb.KeyValue{strKV("log.file.name", "auth.log")},
							},
						},
					},
				},
			},
		},
	}

	logsBytes, _ := proto.Marshal(logsReq)
	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/logs", port), "application/x-protobuf", bytes.NewReader(logsBytes))
	if err != nil {
		t.Fatalf("POST /v1/logs failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for /v1/logs, got %d", resp.StatusCode)
	}

	select {
	case msg := <-msgChan:
		if msg.Topic != "rb_syslog" {
			t.Errorf("Expected topic rb_syslog, got %q", msg.Topic)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(msg.Value, &doc); err != nil {
			t.Fatalf("Invalid log JSON: %v", err)
		}
		if doc["type"] != "otel_log" || doc["severity"] != "WARN" {
			t.Errorf("Unexpected log fields: %+v", doc)
		}
		if doc["src_ip"] != "10.1.2.3" || doc["dst_ip"] != "192.168.1.10" || doc["username"] != "admin" {
			t.Errorf("Expected KV + schema standardization (src_ip, dst_ip, username), got: %+v", doc)
		}
		if doc["trace_id"] != "0102030405060708090a0b0c0d0e0f10" {
			t.Errorf("Unexpected trace_id: %v", doc["trace_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for log message")
	}

	// 2. Send OTLP Traces request
	tracesReq := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			{
				Resource: &resourcepb.Resource{
					Attributes: []*commonpb.KeyValue{strKV("service.name", "payment-svc")},
				},
				ScopeSpans: []*tracepb.ScopeSpans{
					{
						Spans: []*tracepb.Span{
							{
								TraceId:           []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:            []byte{1, 2, 3, 4, 5, 6, 7, 8},
								ParentSpanId:      []byte{8, 7, 6, 5, 4, 3, 2, 1},
								Name:              "POST /charge",
								Kind:              tracepb.Span_SPAN_KIND_SERVER,
								StartTimeUnixNano: 1730000020000000000,
								EndTimeUnixNano:   1730000020025000000, // 25ms
								Attributes:        []*commonpb.KeyValue{intKV("http.response.status_code", 200)},
								Status: &tracepb.Status{
									Code: tracepb.Status_STATUS_CODE_OK,
								},
							},
						},
					},
				},
			},
		},
	}

	tracesBytes, _ := proto.Marshal(tracesReq)
	tResp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/traces", port), "application/x-protobuf", bytes.NewReader(tracesBytes))
	if err != nil {
		t.Fatalf("POST /v1/traces failed: %v", err)
	}
	tResp.Body.Close()
	if tResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for /v1/traces, got %d", tResp.StatusCode)
	}

	select {
	case msg := <-msgChan:
		if msg.Topic != "rb_trace" {
			t.Errorf("Expected topic rb_trace, got %q", msg.Topic)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(msg.Value, &doc); err != nil {
			t.Fatalf("Invalid trace JSON: %v", err)
		}
		if doc["type"] != "otel_trace" || doc["span_name"] != "POST /charge" || doc["duration_ms"] != 25.0 {
			t.Errorf("Unexpected trace fields: %+v", doc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for trace message")
	}
}

func TestOTLPgRPC_AllSignalsAndIPFilter(t *testing.T) {
	port := getFreePort(t)
	cfg := config.ListenerConfig{
		Name:         "test-otlp-grpc",
		Proto:        "otlp_grpc",
		Bind:         "127.0.0.1",
		Port:         port,
		MetricsTopic: "rb_monitor",
		LogsTopic:    "rb_syslog",
		TracesTopic:  "rb_trace",
		MaxMsgSize:   4 * 1024 * 1024,
	}

	l := NewOTLPListener(cfg)
	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start gRPC failed: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient failed: %v", err)
	}
	defer conn.Close()

	// 1. Export Metrics via gRPC
	mClient := colmetricspb.NewMetricsServiceClient(conn)
	_, err = mClient.Export(ctx, &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			{
				Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strKV("host.name", "grpc-host")}},
				ScopeMetrics: []*metricspb.ScopeMetrics{
					{
						Metrics: []*metricspb.Metric{
							{
								Name: "system.memory.usage",
								Data: &metricspb.Metric_Sum{
									Sum: &metricspb.Sum{
										IsMonotonic: true,
										DataPoints: []*metricspb.NumberDataPoint{
											{
												TimeUnixNano: 1730000030000000000,
												Value:        &metricspb.NumberDataPoint_AsInt{AsInt: 1048576},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("gRPC Metrics Export failed: %v", err)
	}

	select {
	case msg := <-msgChan:
		if msg.Topic != "rb_monitor" {
			t.Errorf("Expected topic rb_monitor, got %q", msg.Topic)
		}
		var doc map[string]interface{}
		_ = json.Unmarshal(msg.Value, &doc)
		if doc["metric_name"] != "system.memory.usage" || doc["value"] != float64(1048576) || doc["sensor_ip"] != "127.0.0.1" {
			t.Errorf("Unexpected gRPC metric doc: %+v", doc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for gRPC metric")
	}

	// 2. Test IP Blacklist on gRPC
	portBlocked := getFreePort(t)
	blockedCfg := cfg
	blockedCfg.Port = portBlocked
	blockedCfg.BlacklistIPs = []string{"127.0.0.1"}

	lBlocked := NewOTLPListener(blockedCfg)
	if err := lBlocked.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start blocked gRPC failed: %v", err)
	}
	defer func() { _ = lBlocked.Stop() }()

	time.Sleep(50 * time.Millisecond)

	connBlocked, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", portBlocked), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient failed: %v", err)
	}
	defer connBlocked.Close()

	_, err = colmetricspb.NewMetricsServiceClient(connBlocked).Export(ctx, &colmetricspb.ExportMetricsServiceRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("Expected codes.PermissionDenied for blacklisted IP, got %v", err)
	}
}

func TestOTLP_SignalAwareEnrichmentAndOptionalTraces(t *testing.T) {
	port := getFreePort(t)
	cfg := config.ListenerConfig{
		Name:          "test-otlp-signal-enrichment",
		Proto:         "otlp_http",
		Bind:          "127.0.0.1",
		Port:          port,
		EnrichmentKey: "sensor_ip",
		EnrichmentMap: map[string]map[string]interface{}{
			"127.0.0.1": {
				"metrics": map[string]interface{}{
					"sensor_uuid": "uuid-snmp-monitor",
					"sensor_name": "snmp-monitor-01",
				},
				"logs": map[string]interface{}{
					"sensor_uuid": "uuid-vault-logs",
					"sensor_name": "vault-sensor-01",
				},
				"traces": map[string]interface{}{
					"sensor_uuid": "uuid-apm-trace",
					"sensor_name": "trace-sensor-01",
				},
			},
		},
	}

	l := NewOTLPListener(cfg)
	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := l.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = l.Stop() }()

	time.Sleep(50 * time.Millisecond)

	// 1. Send Metric -> should go to rb_monitor with Monitor sensor enrichment
	mReq := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			{
				ScopeMetrics: []*metricspb.ScopeMetrics{
					{
						Metrics: []*metricspb.Metric{
							{
								Name: "system.cpu.load",
								Data: &metricspb.Metric_Gauge{
									Gauge: &metricspb.Gauge{
										DataPoints: []*metricspb.NumberDataPoint{
											{Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: 1.25}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	mBytes, _ := proto.Marshal(mReq)
	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/metrics", port), "application/x-protobuf", bytes.NewReader(mBytes))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/metrics failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	select {
	case msg := <-msgChan:
		if msg.Topic != "rb_monitor" {
			t.Errorf("Expected default metrics topic rb_monitor, got %q", msg.Topic)
		}
		var doc map[string]interface{}
		_ = json.Unmarshal(msg.Value, &doc)
		if doc["sensor_uuid"] != "uuid-snmp-monitor" || doc["sensor_name"] != "snmp-monitor-01" {
			t.Errorf("Expected Monitor enrichment (uuid-snmp-monitor / snmp-monitor-01), got %+v", doc)
		}
		if _, leaked := doc["metrics"]; leaked {
			t.Errorf("Expected nested 'metrics' map not to leak into flat JSON: %+v", doc)
		}
		if _, leaked := doc["logs"]; leaked {
			t.Errorf("Expected nested 'logs' map not to leak into flat JSON: %+v", doc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for metric message")
	}

	// 2. Send Log -> should go to rb_vault with Vault sensor enrichment
	lReq := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{
			{
				ScopeLogs: []*logspb.ScopeLogs{
					{
						LogRecords: []*logspb.LogRecord{
							{
								SeverityText: "INFO",
								Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "test vault log"}},
							},
						},
					},
				},
			},
		},
	}
	lBytes, _ := proto.Marshal(lReq)
	lResp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/logs", port), "application/x-protobuf", bytes.NewReader(lBytes))
	if err != nil || lResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/logs failed: err=%v status=%v", err, lResp)
	}
	lResp.Body.Close()

	select {
	case msg := <-msgChan:
		if msg.Topic != "rb_vault" {
			t.Errorf("Expected default logs topic rb_vault, got %q", msg.Topic)
		}
		var doc map[string]interface{}
		_ = json.Unmarshal(msg.Value, &doc)
		if doc["sensor_uuid"] != "uuid-vault-logs" || doc["sensor_name"] != "vault-sensor-01" {
			t.Errorf("Expected Vault enrichment (uuid-vault-logs / vault-sensor-01), got %+v", doc)
		}
		if _, leaked := doc["logs"]; leaked {
			t.Errorf("Expected nested 'logs' map not to leak into flat JSON: %+v", doc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for log message")
	}

	// 3. Send Trace when TracesTopic is unset ("") -> returns 200 OK and drops trace
	tReq := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			{
				ScopeSpans: []*tracepb.ScopeSpans{
					{
						Spans: []*tracepb.Span{{Name: "GET /ignored"}},
					},
				},
			},
		},
	}
	tBytes, _ := proto.Marshal(tReq)
	tResp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/traces", port), "application/x-protobuf", bytes.NewReader(tBytes))
	if err != nil || tResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/traces failed: err=%v status=%v", err, tResp)
	}
	tResp.Body.Close()

	select {
	case msg := <-msgChan:
		t.Errorf("Expected trace to be dropped when TracesTopic is empty, but got message on topic %q: %s", msg.Topic, string(msg.Value))
	case <-time.After(100 * time.Millisecond):
		// Expected: no message emitted
	}
}

func TestOTLPForwardedClientIP(t *testing.T) {
	httpPort := getFreePort(t)
	grpcPort := getFreePort(t)

	enrichmentMap := map[string]map[string]interface{}{
		"10.20.20.10": {
			"metrics": map[string]interface{}{
				"sensor_uuid": "uuid-proxied-monitor",
				"sensor_name": "proxied-snmp-01",
			},
		},
	}

	httpCfg := config.ListenerConfig{
		Name:          "otlp-http-proxy-test",
		Proto:         "otlp_http",
		Bind:          "127.0.0.1",
		Port:          httpPort,
		MaxMsgSize:    4194304,
		EnrichmentKey: "sensor_ip",
		EnrichmentMap: enrichmentMap,
		BlacklistIPs:  []string{"10.99.99.99"},
	}

	grpcCfg := config.ListenerConfig{
		Name:          "otlp-grpc-proxy-test",
		Proto:         "otlp_grpc",
		Bind:          "127.0.0.1",
		Port:          grpcPort,
		MaxMsgSize:    4194304,
		EnrichmentKey: "sensor_ip",
		EnrichmentMap: enrichmentMap,
		BlacklistIPs:  []string{"10.99.99.99"},
	}

	msgChan := make(chan *kafka.Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lHTTP := NewOTLPListener(httpCfg)
	if err := lHTTP.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start HTTP failed: %v", err)
	}
	defer func() { _ = lHTTP.Stop() }()

	lGRPC := NewOTLPListener(grpcCfg)
	if err := lGRPC.Start(ctx, msgChan); err != nil {
		t.Fatalf("Start gRPC failed: %v", err)
	}
	defer func() { _ = lGRPC.Stop() }()

	time.Sleep(50 * time.Millisecond)

	mReq := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			{
				ScopeMetrics: []*metricspb.ScopeMetrics{
					{
						Metrics: []*metricspb.Metric{
							{
								Name: "system.cpu.load",
								Data: &metricspb.Metric_Gauge{
									Gauge: &metricspb.Gauge{
										DataPoints: []*metricspb.NumberDataPoint{
											{
												TimeUnixNano: 1730000000000000000,
												Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 0.55},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	mBytes, _ := proto.Marshal(mReq)

	// 1. HTTP with X-Forwarded-For from loopback Nginx proxy -> resolves 10.20.20.10
	reqHTTP, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/metrics", httpPort), bytes.NewReader(mBytes))
	reqHTTP.Header.Set("Content-Type", "application/x-protobuf")
	reqHTTP.Header.Set("X-Forwarded-For", "10.20.20.10, 127.0.0.1")
	respHTTP, err := http.DefaultClient.Do(reqHTTP)
	if err != nil || respHTTP.StatusCode != http.StatusOK {
		t.Fatalf("HTTP request failed: err=%v status=%v", err, respHTTP)
	}
	_ = respHTTP.Body.Close()

	select {
	case msg := <-msgChan:
		var doc map[string]interface{}
		_ = json.Unmarshal(msg.Value, &doc)
		if doc["sensor_ip"] != "10.20.20.10" {
			t.Errorf("Expected sensor_ip 10.20.20.10 from X-Forwarded-For, got %v", doc["sensor_ip"])
		}
		if doc["sensor_uuid"] != "uuid-proxied-monitor" {
			t.Errorf("Expected enrichment for 10.20.20.10 (uuid-proxied-monitor), got %+v", doc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for proxied HTTP metric")
	}

	// 2. HTTP with blacklisted X-Real-IP -> 403 Forbidden
	reqBlocked, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/metrics", httpPort), bytes.NewReader(mBytes))
	reqBlocked.Header.Set("Content-Type", "application/x-protobuf")
	reqBlocked.Header.Set("X-Real-IP", "10.99.99.99")
	respBlocked, err := http.DefaultClient.Do(reqBlocked)
	if err != nil {
		t.Fatalf("HTTP blocked request error: %v", err)
	}
	_ = respBlocked.Body.Close()
	if respBlocked.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for blacklisted X-Real-IP, got %d", respBlocked.StatusCode)
	}

	// 3. gRPC with x-real-ip metadata from loopback Nginx proxy -> resolves 10.20.20.10
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", grpcPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient failed: %v", err)
	}
	defer conn.Close()

	mClient := colmetricspb.NewMetricsServiceClient(conn)
	mdCtx := metadata.AppendToOutgoingContext(ctx, "x-real-ip", "10.20.20.10")
	if _, err := mClient.Export(mdCtx, mReq); err != nil {
		t.Fatalf("gRPC Export with x-real-ip failed: %v", err)
	}

	select {
	case msg := <-msgChan:
		var doc map[string]interface{}
		_ = json.Unmarshal(msg.Value, &doc)
		if doc["sensor_ip"] != "10.20.20.10" {
			t.Errorf("Expected sensor_ip 10.20.20.10 from gRPC x-real-ip, got %v", doc["sensor_ip"])
		}
		if doc["sensor_uuid"] != "uuid-proxied-monitor" {
			t.Errorf("Expected enrichment for 10.20.20.10 (uuid-proxied-monitor), got %+v", doc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for proxied gRPC metric")
	}

	// 4. gRPC with blacklisted x-forwarded-for (even if attacker prepends a spoofed allowed IP) -> PermissionDenied
	mdBlockedCtx := metadata.AppendToOutgoingContext(ctx, "x-forwarded-for", "10.20.20.10, 10.99.99.99")
	_, err = mClient.Export(mdBlockedCtx, mReq)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied for blacklisted gRPC x-forwarded-for, got %v", err)
	}

	// 5. Non-loopback peerAddr must NOT trust spoofed X-Real-IP / X-Forwarded-For headers
	if got := resolveClientIP("192.168.1.50:54321", "10.20.20.10", "10.20.20.10"); got != "192.168.1.50" {
		t.Errorf("Expected non-loopback peer IP 192.168.1.50 to ignore X-Real-IP, got %q", got)
	}

	// 6. Canonicalizes IPv4-mapped IPv6 and picks rightmost non-loopback hop in X-Forwarded-For
	if got := resolveClientIP("127.0.0.1:45678", "::ffff:10.20.20.10", ""); got != "10.20.20.10" {
		t.Errorf("Expected canonicalized IPv4 10.20.20.10, got %q", got)
	}
	if got := resolveClientIP("127.0.0.1:45678", "invalid-ip", "1.2.3.4, 10.20.20.10, 127.0.0.1"); got != "10.20.20.10" {
		t.Errorf("Expected rightmost non-loopback XFF hop 10.20.20.10 when X-Real-IP is invalid, got %q", got)
	}
}
