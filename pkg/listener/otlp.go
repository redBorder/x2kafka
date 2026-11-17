package listener

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // Register gzip compressor for gRPC OTLP clients
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"x2kafka/pkg/config"
	"x2kafka/pkg/decoder"
	"x2kafka/pkg/kafka"
	"x2kafka/pkg/security"
	"x2kafka/pkg/stats"
)

type OTLPListener struct {
	cfg           config.ListenerConfig
	metricsCfg    config.ListenerConfig
	logsCfg       config.ListenerConfig
	tracesCfg     config.ListenerConfig
	decoder       *decoder.Decoder
	ipFilter      *security.IPFilter
	excludeFields map[string]bool
	httpServer    *http.Server
	grpcServer    *grpc.Server
	grpcLis       net.Listener
	msgChan       chan<- *kafka.Message
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
}

type otlpMetricsGRPCServer struct {
	colmetricspb.UnimplementedMetricsServiceServer
	parent *OTLPListener
}

type otlpLogsGRPCServer struct {
	collogspb.UnimplementedLogsServiceServer
	parent *OTLPListener
}

type otlpTraceGRPCServer struct {
	coltracepb.UnimplementedTraceServiceServer
	parent *OTLPListener
}

func NewOTLPListener(cfg config.ListenerConfig) *OTLPListener {
	if cfg.MaxMsgSize <= 0 {
		cfg.MaxMsgSize = 4 * 1024 * 1024
	}
	if cfg.MetricsTopic == "" {
		if cfg.Topic != "" {
			cfg.MetricsTopic = cfg.Topic
		} else {
			cfg.MetricsTopic = "rb_monitor"
		}
	}
	if cfg.LogsTopic == "" {
		if cfg.Topic != "" {
			cfg.LogsTopic = cfg.Topic
		} else {
			cfg.LogsTopic = "rb_vault"
		}
	}
	if cfg.TracesTopic == "" && cfg.Topic != "" {
		cfg.TracesTopic = cfg.Topic
	}
	if cfg.Port == 0 {
		if cfg.Proto == "otlp_grpc" {
			cfg.Port = 4317
		} else {
			cfg.Port = 4318
		}
	}

	excl := make(map[string]bool, len(cfg.ExcludeFields))
	for _, f := range cfg.ExcludeFields {
		if f != "" {
			excl[f] = true
		}
	}

	return &OTLPListener{
		cfg:           cfg,
		metricsCfg:    buildSignalConfig(cfg, "metrics", cfg.MetricsTopic),
		logsCfg:       buildSignalConfig(cfg, "logs", cfg.LogsTopic),
		tracesCfg:     buildSignalConfig(cfg, "traces", cfg.TracesTopic),
		decoder:       decoder.NewDecoder(),
		ipFilter:      security.NewIPFilter(cfg.AllowedIPs, cfg.BlacklistIPs),
		excludeFields: excl,
	}
}

var reservedOTLPSignalKeys = map[string]bool{
	"metrics":    true,
	"metric":     true,
	"logs":       true,
	"log":        true,
	"traces":     true,
	"trace":      true,
	"rb_monitor": true,
	"rb_vault":   true,
	"rb_syslog":  true,
	"rb_trace":   true,
}

func buildSignalConfig(base config.ListenerConfig, signal string, targetTopic string) config.ListenerConfig {
	out := base
	if len(base.EnrichmentMap) == 0 {
		return out
	}

	singular := strings.TrimSuffix(signal, "s")
	resolvedMap := make(map[string]map[string]interface{}, len(base.EnrichmentMap))

	// First pass: resolve normal entries (and nested signal sub-maps)
	for key, entry := range base.EnrichmentMap {
		if idx := strings.LastIndex(key, ":"); idx != -1 {
			suffix := key[idx+1:]
			if reservedOTLPSignalKeys[suffix] {
				continue
			}
		}

		shared := make(map[string]interface{})
		hasSignalSubMap := false
		for k, v := range entry {
			if reservedOTLPSignalKeys[k] {
				if _, isMap := v.(map[string]interface{}); isMap {
					hasSignalSubMap = true
					continue
				}
			}
			shared[k] = v
		}

		var signalFields map[string]interface{}
		for _, candidateKey := range []string{signal, singular, targetTopic} {
			if candidateKey == "" {
				continue
			}
			if subRaw, ok := entry[candidateKey].(map[string]interface{}); ok {
				if inner, hasInner := subRaw["enrichment"].(map[string]interface{}); hasInner {
					signalFields = inner
				} else {
					signalFields = subRaw
				}
				break
			}
		}

		if signalFields != nil {
			merged := make(map[string]interface{}, len(shared)+len(signalFields))
			for k, v := range shared {
				merged[k] = v
			}
			for k, v := range signalFields {
				merged[k] = v
			}
			resolvedMap[key] = merged
		} else if !hasSignalSubMap && len(shared) > 0 {
			resolvedMap[key] = shared
		} else if len(shared) > 0 {
			resolvedMap[key] = shared
		}
	}

	// Second pass: composite keys like "<ip>:metrics", "<ip>:logs", "<ip>:traces", "<ip>:<topic>"
	for key, entry := range base.EnrichmentMap {
		idx := strings.LastIndex(key, ":")
		if idx == -1 {
			continue
		}
		baseKey := key[:idx]
		suffix := key[idx+1:]
		if suffix == signal || suffix == singular || (targetTopic != "" && suffix == targetTopic) {
			merged := make(map[string]interface{}, len(entry))
			if existing, ok := resolvedMap[baseKey]; ok {
				for k, v := range existing {
					merged[k] = v
				}
			}
			for k, v := range entry {
				merged[k] = v
			}
			resolvedMap[baseKey] = merged
		}
	}

	out.EnrichmentMap = resolvedMap
	return out
}

func (o *OTLPListener) Name() string {
	if o.cfg.Name != "" {
		return o.cfg.Name
	}
	proto := o.cfg.Proto
	if proto == "" {
		proto = "otlp_http"
	}
	return fmt.Sprintf("%s-%s:%d", proto, o.cfg.Bind, o.cfg.Port)
}

func (o *OTLPListener) Start(ctx context.Context, msgChan chan<- *kafka.Message) error {
	o.ctx, o.cancel = context.WithCancel(ctx)
	o.msgChan = msgChan

	bindAddr := fmt.Sprintf("%s:%d", o.cfg.Bind, o.cfg.Port)
	if o.cfg.Bind == "" {
		bindAddr = fmt.Sprintf(":%d", o.cfg.Port)
	}

	if o.cfg.Proto == "otlp_grpc" {
		return o.startGRPC(bindAddr)
	}
	return o.startHTTP(bindAddr)
}

func (o *OTLPListener) startHTTP(bindAddr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", o.handleHTTPRequest)

	o.httpServer = &http.Server{
		Addr:         bindAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		var err error
		if o.cfg.Proto == "otlp_https" || (o.cfg.TLSCert != "" && o.cfg.TLSKey != "") {
			log.Printf("[%s] Starting OTLP HTTPS listener on %s", o.Name(), bindAddr)
			err = o.httpServer.ListenAndServeTLS(o.cfg.TLSCert, o.cfg.TLSKey)
		} else {
			log.Printf("[%s] Starting OTLP HTTP listener on %s", o.Name(), bindAddr)
			err = o.httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			stats.IncListenerError(o.Name())
			log.Printf("[%s] OTLP HTTP server error: %v", o.Name(), err)
		}
	}()

	return nil
}

func (o *OTLPListener) startGRPC(bindAddr string) error {
	lis, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s for OTLP gRPC: %w", bindAddr, err)
	}
	o.grpcLis = lis

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(o.cfg.MaxMsgSize),
	}
	if o.cfg.TLSCert != "" && o.cfg.TLSKey != "" {
		creds, err := credentials.NewServerTLSFromFile(o.cfg.TLSCert, o.cfg.TLSKey)
		if err != nil {
			_ = lis.Close()
			return fmt.Errorf("failed to load OTLP gRPC TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	o.grpcServer = grpc.NewServer(opts...)
	colmetricspb.RegisterMetricsServiceServer(o.grpcServer, &otlpMetricsGRPCServer{parent: o})
	collogspb.RegisterLogsServiceServer(o.grpcServer, &otlpLogsGRPCServer{parent: o})
	coltracepb.RegisterTraceServiceServer(o.grpcServer, &otlpTraceGRPCServer{parent: o})

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		log.Printf("[%s] Starting OTLP gRPC listener on %s", o.Name(), bindAddr)
		if err := o.grpcServer.Serve(lis); err != nil {
			stats.IncListenerError(o.Name())
			log.Printf("[%s] OTLP gRPC server error: %v", o.Name(), err)
		}
	}()

	return nil
}

func (o *OTLPListener) Stop() error {
	if o.cancel != nil {
		o.cancel()
	}
	if o.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = o.httpServer.Shutdown(shutdownCtx)
	}
	if o.grpcServer != nil {
		o.grpcServer.GracefulStop()
	}
	if o.grpcLis != nil {
		_ = o.grpcLis.Close()
	}
	o.wg.Wait()
	return nil
}

func parseCanonicalIP(raw string) (net.IP, string) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return nil, ""
	}
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}
	ip := net.ParseIP(candidate)
	if ip == nil {
		return nil, ""
	}
	return ip, ip.String()
}

func resolveClientIP(peerAddr string, realIP string, forwardedFor string) string {
	srcAddr := peerAddr
	if host, _, err := net.SplitHostPort(srcAddr); err == nil {
		srcAddr = host
	}
	if ip := net.ParseIP(srcAddr); ip != nil && ip.IsLoopback() {
		if _, canon := parseCanonicalIP(realIP); canon != "" {
			return canon
		}
		if forwardedFor != "" {
			parts := strings.Split(forwardedFor, ",")
			fallbackLoopback := ""
			for i := len(parts) - 1; i >= 0; i-- {
				parsed, canon := parseCanonicalIP(parts[i])
				if parsed == nil {
					continue
				}
				if !parsed.IsLoopback() {
					return canon
				}
				if fallbackLoopback == "" {
					fallbackLoopback = canon
				}
			}
			if fallbackLoopback != "" {
				return fallbackLoopback
			}
		}
	}
	return srcAddr
}

func (o *OTLPListener) extractGRPCClientIP(ctx context.Context) (string, error) {
	peerAddr := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		peerAddr = p.Addr.String()
	}
	realIP := ""
	forwardedFor := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-real-ip"); len(vals) > 0 {
			realIP = vals[0]
		}
		if vals := md.Get("x-forwarded-for"); len(vals) > 0 {
			forwardedFor = vals[0]
		}
	}
	srcAddr := resolveClientIP(peerAddr, realIP, forwardedFor)
	if !o.ipFilter.IsAllowed(srcAddr) {
		stats.IncListenerError(o.Name())
		return "", status.Error(codes.PermissionDenied, "IP not allowed")
	}
	return srcAddr, nil
}

func (m *otlpMetricsGRPCServer) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	srcAddr, err := m.parent.extractGRPCClientIP(ctx)
	if err != nil {
		return nil, err
	}
	stats.IncMessagesReceived(m.parent.Name(), proto.Size(req))
	m.parent.processMetrics(req, srcAddr, "")
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func (l *otlpLogsGRPCServer) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	srcAddr, err := l.parent.extractGRPCClientIP(ctx)
	if err != nil {
		return nil, err
	}
	stats.IncMessagesReceived(l.parent.Name(), proto.Size(req))
	l.parent.processLogs(req, srcAddr, "")
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (t *otlpTraceGRPCServer) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	srcAddr, err := t.parent.extractGRPCClientIP(ctx)
	if err != nil {
		return nil, err
	}
	stats.IncMessagesReceived(t.parent.Name(), proto.Size(req))
	t.parent.processTraces(req, srcAddr, "")
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

func (o *OTLPListener) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	srcAddr := resolveClientIP(r.RemoteAddr, r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For"))

	if !o.ipFilter.IsAllowed(srcAddr) {
		stats.IncListenerError(o.Name())
		http.Error(w, "Forbidden: IP not allowed", http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		stats.IncListenerError(o.Name())
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(o.cfg.MaxMsgSize)))
	if err != nil {
		stats.IncListenerError(o.Name())
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		stats.IncListenerError(o.Name())
		http.Error(w, "Empty body", http.StatusBadRequest)
		return
	}

	// Decompress gzip / zlib / deflate payloads
	contentEncoding := strings.ToLower(r.Header.Get("Content-Encoding"))
	isGzip := contentEncoding == "gzip" || (len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b)
	isDeflate := contentEncoding == "deflate" || contentEncoding == "zlib" || (len(body) >= 2 && body[0] == 0x78)

	if isGzip {
		if gzReader, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if decompressed, err := io.ReadAll(gzReader); err == nil && len(decompressed) > 0 {
				body = decompressed
			}
			_ = gzReader.Close()
		}
	} else if isDeflate {
		if zReader, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			if decompressed, err := io.ReadAll(zReader); err == nil && len(decompressed) > 0 {
				body = decompressed
			}
			_ = zReader.Close()
		} else {
			fReader := flate.NewReader(bytes.NewReader(body))
			if decompressed, err := io.ReadAll(fReader); err == nil && len(decompressed) > 0 {
				body = decompressed
			}
			_ = fReader.Close()
		}
	}

	stats.IncMessagesReceived(o.Name(), len(body))

	// Parse URL path: supports /v1/{metrics,logs,traces} and /rbdata/<sensor_uuid>/v1/{metrics,logs,traces}
	urlPath := strings.Trim(r.URL.Path, "/")
	pathParts := strings.Split(urlPath, "/")
	sensorUUID := ""
	signal := ""

	if len(pathParts) >= 4 && pathParts[0] == "rbdata" && pathParts[2] == "v1" {
		sensorUUID = pathParts[1]
		signal = pathParts[3]
	} else if len(pathParts) >= 2 && pathParts[len(pathParts)-2] == "v1" {
		signal = pathParts[len(pathParts)-1]
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	isJSONPayload := strings.Contains(contentType, "json") || (len(body) > 0 && body[0] == '{')

	unmarshalOTLP := func(msg proto.Message) error {
		if isJSONPayload {
			unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
			return unmarshaler.Unmarshal(body, msg)
		}
		return proto.Unmarshal(body, msg)
	}

	writeOTLPResponse := func(resp proto.Message) {
		if isJSONPayload {
			w.Header().Set("Content-Type", "application/json")
			out, _ := protojson.Marshal(resp)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		out, _ := proto.Marshal(resp)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	}

	switch signal {
	case "metrics":
		var req colmetricspb.ExportMetricsServiceRequest
		if err := unmarshalOTLP(&req); err != nil {
			stats.IncListenerError(o.Name())
			http.Error(w, fmt.Sprintf("Invalid OTLP metrics payload: %v", err), http.StatusBadRequest)
			return
		}
		o.processMetrics(&req, srcAddr, sensorUUID)
		writeOTLPResponse(&colmetricspb.ExportMetricsServiceResponse{})

	case "logs":
		var req collogspb.ExportLogsServiceRequest
		if err := unmarshalOTLP(&req); err != nil {
			stats.IncListenerError(o.Name())
			http.Error(w, fmt.Sprintf("Invalid OTLP logs payload: %v", err), http.StatusBadRequest)
			return
		}
		o.processLogs(&req, srcAddr, sensorUUID)
		writeOTLPResponse(&collogspb.ExportLogsServiceResponse{})

	case "traces":
		var req coltracepb.ExportTraceServiceRequest
		if err := unmarshalOTLP(&req); err != nil {
			stats.IncListenerError(o.Name())
			http.Error(w, fmt.Sprintf("Invalid OTLP traces payload: %v", err), http.StatusBadRequest)
			return
		}
		o.processTraces(&req, srcAddr, sensorUUID)
		writeOTLPResponse(&coltracepb.ExportTraceServiceResponse{})

	default:
		stats.IncListenerError(o.Name())
		http.Error(w, "Unsupported OTLP endpoint (expected /v1/metrics, /v1/logs, or /v1/traces)", http.StatusNotFound)
	}
}

func (o *OTLPListener) processMetrics(req *colmetricspb.ExportMetricsServiceRequest, srcAddr string, sensorUUID string) {
	for _, rm := range req.GetResourceMetrics() {
		resAttrs := extractAttributes(rm.GetResource().GetAttributes())
		for _, sm := range rm.GetScopeMetrics() {
			scopeName := sm.GetScope().GetName()
			scopeVersion := sm.GetScope().GetVersion()

			for _, metric := range sm.GetMetrics() {
				metricName := metric.GetName()
				metricUnit := metric.GetUnit()

				switch data := metric.GetData().(type) {
				case *metricspb.Metric_Gauge:
					for _, dp := range data.Gauge.GetDataPoints() {
						doc := o.newBaseDoc("otel_metric", dp.GetTimeUnixNano(), srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)
						doc["metric_name"] = metricName
						doc["metric_type"] = "gauge"
						if metricUnit != "" {
							doc["metric_unit"] = metricUnit
						}
						setNumberDataPointValue(doc, dp)
						mergeAttributes(doc, dp.GetAttributes())
						o.emitDoc(doc, o.metricsCfg, o.cfg.MetricsTopic, srcAddr)
					}

				case *metricspb.Metric_Sum:
					for _, dp := range data.Sum.GetDataPoints() {
						doc := o.newBaseDoc("otel_metric", dp.GetTimeUnixNano(), srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)
						doc["metric_name"] = metricName
						doc["metric_type"] = "sum"
						doc["is_monotonic"] = data.Sum.GetIsMonotonic()
						if metricUnit != "" {
							doc["metric_unit"] = metricUnit
						}
						setNumberDataPointValue(doc, dp)
						mergeAttributes(doc, dp.GetAttributes())
						o.emitDoc(doc, o.metricsCfg, o.cfg.MetricsTopic, srcAddr)
					}

				case *metricspb.Metric_Histogram:
					for _, dp := range data.Histogram.GetDataPoints() {
						doc := o.newBaseDoc("otel_metric", dp.GetTimeUnixNano(), srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)
						doc["metric_name"] = metricName
						doc["metric_type"] = "histogram"
						if metricUnit != "" {
							doc["metric_unit"] = metricUnit
						}
						doc["count"] = dp.GetCount()
						if dp.Sum != nil {
							doc["sum"] = dp.GetSum()
							doc["value"] = dp.GetSum()
						}
						if dp.Min != nil {
							doc["min"] = dp.GetMin()
						}
						if dp.Max != nil {
							doc["max"] = dp.GetMax()
						}
						mergeAttributes(doc, dp.GetAttributes())
						o.emitDoc(doc, o.metricsCfg, o.cfg.MetricsTopic, srcAddr)
					}

				case *metricspb.Metric_ExponentialHistogram:
					for _, dp := range data.ExponentialHistogram.GetDataPoints() {
						doc := o.newBaseDoc("otel_metric", dp.GetTimeUnixNano(), srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)
						doc["metric_name"] = metricName
						doc["metric_type"] = "exponential_histogram"
						if metricUnit != "" {
							doc["metric_unit"] = metricUnit
						}
						doc["count"] = dp.GetCount()
						if dp.Sum != nil {
							doc["sum"] = dp.GetSum()
							doc["value"] = dp.GetSum()
						}
						if dp.Min != nil {
							doc["min"] = dp.GetMin()
						}
						if dp.Max != nil {
							doc["max"] = dp.GetMax()
						}
						mergeAttributes(doc, dp.GetAttributes())
						o.emitDoc(doc, o.metricsCfg, o.cfg.MetricsTopic, srcAddr)
					}

				case *metricspb.Metric_Summary:
					for _, dp := range data.Summary.GetDataPoints() {
						doc := o.newBaseDoc("otel_metric", dp.GetTimeUnixNano(), srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)
						doc["metric_name"] = metricName
						doc["metric_type"] = "summary"
						if metricUnit != "" {
							doc["metric_unit"] = metricUnit
						}
						doc["count"] = dp.GetCount()
						doc["sum"] = dp.GetSum()
						doc["value"] = dp.GetSum()
						mergeAttributes(doc, dp.GetAttributes())
						o.emitDoc(doc, o.metricsCfg, o.cfg.MetricsTopic, srcAddr)
					}
				}
			}
		}
	}
}

func (o *OTLPListener) processLogs(req *collogspb.ExportLogsServiceRequest, srcAddr string, sensorUUID string) {
	for _, rl := range req.GetResourceLogs() {
		resAttrs := extractAttributes(rl.GetResource().GetAttributes())
		for _, sl := range rl.GetScopeLogs() {
			scopeName := sl.GetScope().GetName()
			scopeVersion := sl.GetScope().GetVersion()

			for _, lr := range sl.GetLogRecords() {
				tsNano := lr.GetTimeUnixNano()
				if tsNano == 0 {
					tsNano = lr.GetObservedTimeUnixNano()
				}
				doc := o.newBaseDoc("otel_log", tsNano, srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)

				if lr.GetSeverityText() != "" {
					doc["severity"] = lr.GetSeverityText()
				}
				if lr.GetSeverityNumber() != 0 {
					doc["severity_number"] = int(lr.GetSeverityNumber())
				}
				if len(lr.GetTraceId()) > 0 {
					doc["trace_id"] = hex.EncodeToString(lr.GetTraceId())
				}
				if len(lr.GetSpanId()) > 0 {
					doc["span_id"] = hex.EncodeToString(lr.GetSpanId())
				}

				if body := lr.GetBody(); body != nil {
					if kvList := body.GetKvlistValue(); kvList != nil {
						mergeAttributes(doc, kvList.GetValues())
						if b, err := json.Marshal(extractAttributes(kvList.GetValues())); err == nil {
							doc["message"] = string(b)
						}
					} else {
						val := anyValueToInterface(body)
						if val != nil {
							doc["message"] = fmt.Sprintf("%v", val)
						}
					}
				}

				mergeAttributes(doc, lr.GetAttributes())
				o.emitDoc(doc, o.logsCfg, o.cfg.LogsTopic, srcAddr)
			}
		}
	}
}

func (o *OTLPListener) processTraces(req *coltracepb.ExportTraceServiceRequest, srcAddr string, sensorUUID string) {
	if o.cfg.TracesTopic == "" && len(o.cfg.EnrichmentRules) == 0 {
		return
	}
	for _, rs := range req.GetResourceSpans() {
		resAttrs := extractAttributes(rs.GetResource().GetAttributes())
		for _, ss := range rs.GetScopeSpans() {
			scopeName := ss.GetScope().GetName()
			scopeVersion := ss.GetScope().GetVersion()

			for _, span := range ss.GetSpans() {
				startNano := span.GetStartTimeUnixNano()
				endNano := span.GetEndTimeUnixNano()
				doc := o.newBaseDoc("otel_trace", startNano, srcAddr, sensorUUID, resAttrs, scopeName, scopeVersion)

				if len(span.GetTraceId()) > 0 {
					doc["trace_id"] = hex.EncodeToString(span.GetTraceId())
				}
				if len(span.GetSpanId()) > 0 {
					doc["span_id"] = hex.EncodeToString(span.GetSpanId())
				}
				if len(span.GetParentSpanId()) > 0 {
					doc["parent_span_id"] = hex.EncodeToString(span.GetParentSpanId())
				}
				doc["span_name"] = span.GetName()
				doc["span_kind"] = span.GetKind().String()
				doc["start_time_unix_nano"] = startNano
				doc["end_time_unix_nano"] = endNano
				if endNano >= startNano && startNano > 0 {
					durNs := endNano - startNano
					doc["duration_ns"] = durNs
					doc["duration_ms"] = float64(durNs) / 1e6
				}
				if st := span.GetStatus(); st != nil {
					doc["status_code"] = st.GetCode().String()
					if st.GetMessage() != "" {
						doc["status_message"] = st.GetMessage()
					}
				}

				mergeAttributes(doc, span.GetAttributes())
				o.emitDoc(doc, o.tracesCfg, o.cfg.TracesTopic, srcAddr)
			}
		}
	}
}

func (o *OTLPListener) newBaseDoc(recordType string, timeUnixNano uint64, srcAddr string, sensorUUID string, resAttrs map[string]interface{}, scopeName string, scopeVersion string) map[string]interface{} {
	doc := make(map[string]interface{}, len(resAttrs)+8)
	for k, v := range resAttrs {
		doc[k] = v
	}
	if hostName, ok := resAttrs["host.name"]; ok {
		if _, hasHostname := doc["hostname"]; !hasHostname {
			doc["hostname"] = hostName
		}
	}

	if timeUnixNano > 0 {
		doc["timestamp"] = int64(timeUnixNano / 1e9)
		doc["timestamp_ns"] = timeUnixNano
	} else {
		doc["timestamp"] = time.Now().Unix()
	}

	doc["type"] = recordType
	if srcAddr != "" {
		doc["sensor_ip"] = srcAddr
	}
	if sensorUUID != "" {
		if _, ok := doc["sensor_uuid"]; !ok {
			doc["sensor_uuid"] = sensorUUID
		}
		if _, ok := doc["proxy_uuid"]; !ok {
			doc["proxy_uuid"] = sensorUUID
		}
	}
	if scopeName != "" {
		doc["scope_name"] = scopeName
	}
	if scopeVersion != "" {
		doc["scope_version"] = scopeVersion
	}
	return doc
}

func (o *OTLPListener) emitDoc(doc map[string]interface{}, signalCfg config.ListenerConfig, defaultTopic string, srcAddr string) {
	if len(o.excludeFields) > 0 {
		for k := range o.excludeFields {
			delete(doc, k)
		}
	}

	rawBytes, err := json.Marshal(doc)
	if err != nil {
		return
	}

	formatted, ruleTopic, err := o.decoder.FormatPayloadWithConfigAndTopic(rawBytes, signalCfg, signalCfg.Proto, srcAddr)
	if err != nil || len(formatted) == 0 {
		return
	}

	topic := ruleTopic
	if topic == "" {
		topic = defaultTopic
	}
	if topic == "" {
		topic = signalCfg.Topic
	}
	if topic == "" {
		return
	}

	o.msgChan <- &kafka.Message{
		Topic:     topic,
		Value:     formatted,
		Timestamp: time.Now(),
	}
}

func setNumberDataPointValue(doc map[string]interface{}, dp *metricspb.NumberDataPoint) {
	switch v := dp.GetValue().(type) {
	case *metricspb.NumberDataPoint_AsDouble:
		doc["value"] = v.AsDouble
	case *metricspb.NumberDataPoint_AsInt:
		doc["value"] = v.AsInt
	}
}

func extractAttributes(kvs []*commonpb.KeyValue) map[string]interface{} {
	if len(kvs) == 0 {
		return nil
	}
	res := make(map[string]interface{}, len(kvs))
	for _, kv := range kvs {
		if kv == nil || kv.Key == "" {
			continue
		}
		if val := anyValueToInterface(kv.GetValue()); val != nil {
			res[kv.Key] = val
		}
	}
	return res
}

func mergeAttributes(doc map[string]interface{}, kvs []*commonpb.KeyValue) {
	for _, kv := range kvs {
		if kv == nil || kv.Key == "" {
			continue
		}
		if val := anyValueToInterface(kv.GetValue()); val != nil {
			doc[kv.Key] = val
		}
	}
}

func anyValueToInterface(av *commonpb.AnyValue) interface{} {
	if av == nil {
		return nil
	}
	switch v := av.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.StringValue
	case *commonpb.AnyValue_BoolValue:
		return v.BoolValue
	case *commonpb.AnyValue_IntValue:
		return v.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.AnyValue_BytesValue:
		return hex.EncodeToString(v.BytesValue)
	case *commonpb.AnyValue_ArrayValue:
		if v.ArrayValue == nil {
			return nil
		}
		vals := v.ArrayValue.GetValues()
		arr := make([]interface{}, 0, len(vals))
		for _, item := range vals {
			arr = append(arr, anyValueToInterface(item))
		}
		return arr
	case *commonpb.AnyValue_KvlistValue:
		if v.KvlistValue == nil {
			return nil
		}
		return extractAttributes(v.KvlistValue.GetValues())
	default:
		return nil
	}
}
