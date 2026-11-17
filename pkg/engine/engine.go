package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"x2kafka/pkg/config"
	"x2kafka/pkg/kafka"
	"x2kafka/pkg/listener"
	"x2kafka/pkg/mib"
	"x2kafka/pkg/stats"
)

type Engine struct {
	cfg           *config.Config
	producer      *kafka.Producer
	listeners     []listener.Listener
	msgChan       chan *kafka.Message
	statsServer   *http.Server
	statsListener net.Listener
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

func NewEngine(cfg *config.Config) (*Engine, error) {
	_ = mib.InitMIBs(cfg.MibDirs)

	producerCfg := kafka.ProducerConfig{
		Brokers:        cfg.Brokers,
		Topic:          cfg.Topic,
		BatchSize:      cfg.BatchSize,
		BatchTimeoutMS: cfg.BatchTimeoutMS,
		Async:          cfg.Async,
		Compression:    cfg.Compression,
	}

	producer, err := kafka.NewProducer(producerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	chanSize := cfg.ChannelBufferSize
	if chanSize <= 0 {
		chanSize = 50000
	}

	eng := &Engine{
		cfg:      cfg,
		producer: producer,
		msgChan:  make(chan *kafka.Message, chanSize),
		ctx:      ctx,
		cancel:   cancel,
	}

	for _, lcfg := range cfg.Listeners {
		l, err := createListener(lcfg)
		if err != nil {
			log.Printf("Warning: Failed to instantiate listener '%s' (%s): %v", lcfg.Name, lcfg.Proto, err)
			continue
		}
		stats.RegisterListener(l.Name(), lcfg.Proto)
		eng.listeners = append(eng.listeners, l)
	}

	return eng, nil
}

func createListener(lcfg config.ListenerConfig) (listener.Listener, error) {
	switch lcfg.Proto {
	case "unix", "unixgram":
		return listener.NewUnixListener(lcfg), nil
	case "fifo":
		return listener.NewFifoListener(lcfg), nil
	case "syslog_udp", "syslog_tcp", "syslog_unix":
		return listener.NewSyslogListener(lcfg), nil
	case "snmptrap_udp", "snmptrap_tcp":
		return listener.NewSNMPTrapListener(lcfg), nil
	case "flow", "netflow", "netflow_udp", "ipfix", "sflow", "sflow_udp":
		return listener.NewFlowListener(lcfg), nil
	case "http", "https":
		return listener.NewHTTPListener(lcfg), nil
	case "otlp", "otlp_http", "otlp_https", "otlp_grpc":
		return listener.NewOTLPListener(lcfg), nil
	default:
		return nil, fmt.Errorf("unsupported proto '%s'", lcfg.Proto)
	}
}

func (e *Engine) Start() error {
	if len(e.listeners) == 0 {
		return fmt.Errorf("no valid listeners configured")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", stats.StatsHandler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	if e.cfg.StatsPort > 0 {
		bindAddr := fmt.Sprintf("%s:%d", e.cfg.StatsBind, e.cfg.StatsPort)
		if e.cfg.StatsBind == "" {
			bindAddr = fmt.Sprintf(":%d", e.cfg.StatsPort)
		}

		e.statsServer = &http.Server{
			Addr:         bindAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}

		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			log.Printf("[Engine] Starting Stats HTTP server on %s", bindAddr)
			if err := e.statsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[Engine] Stats server error: %v", err)
			}
		}()
	}

	if e.cfg.StatsSocket != "" {
		socketPath := e.cfg.StatsSocket
		_ = os.Remove(socketPath)

		dir := filepath.Dir(socketPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[Engine] Failed to create socket directory %s: %v", dir, err)
		}

		l, err := net.Listen("unix", socketPath)
		if err != nil {
			log.Printf("[Engine] Failed to listen on stats socket %s: %v", socketPath, err)
		} else {
			_ = os.Chmod(socketPath, 0666)
			e.statsListener = l
			log.Printf("[Engine] IPC stats server listening on unix socket %s", socketPath)

			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				// Serve HTTP over Unix socket AND raw commands like redborder-monitor ("stats", "status", "reset")
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					go e.handleIPCConn(conn, mux)
				}
			}()
		}
	}

	numWorkers := e.cfg.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU() * 2
	}

	for i := 0; i < numWorkers; i++ {
		e.wg.Add(1)
		go e.kafkaWorker(i)
	}

	for _, l := range e.listeners {
		err := l.Start(e.ctx, e.msgChan)
		if err != nil {
			log.Printf("Error starting listener %s: %v", l.Name(), err)
		}
	}

	log.Printf("[Engine] Started %d listeners with %d parallel processing workers (Queue: %d, Compression: %s)",
		len(e.listeners), numWorkers, cap(e.msgChan), e.cfg.Compression)
	return nil
}

func (e *Engine) kafkaWorker(id int) {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			for len(e.msgChan) > 0 {
				msg := <-e.msgChan
				_ = e.producer.Produce(msg)
			}
			return
		case msg, ok := <-e.msgChan:
			if !ok {
				return
			}
			if e.cfg.Debug {
				log.Printf("[DEBUG][Worker %d] Producing message to topic %q (length: %d bytes): %s",
					id, msg.Topic, len(msg.Value), string(msg.Value))
			}
			err := e.producer.Produce(msg)
			if err != nil {
				log.Printf("[Worker %d Error] Kafka produce error for topic %q: %v", id, msg.Topic, err)
			} else if e.cfg.Debug {
				log.Printf("[DEBUG][Worker %d] Successfully published message to topic %q", id, msg.Topic)
			}
		}
	}
}

func (e *Engine) handleIPCConn(conn net.Conn, mux *http.ServeMux) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	peekBytes, err := reader.Peek(4)
	if err == nil {
		reqLine := string(peekBytes)
		if strings.HasPrefix(reqLine, "GET ") || strings.HasPrefix(reqLine, "POST") {
			// standard HTTP request over UDS socket (e.g. curl --unix-socket)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			rw := &socketResponseWriter{conn: conn, header: make(http.Header)}
			mux.ServeHTTP(rw, req)
			return
		}
	}

	// Plain redborder-monitor IPC protocol ("stats", "status", "reset", or empty)
	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	cmd := "stats"
	if n > 0 {
		cmd = strings.TrimSpace(string(buf[:n]))
	}

	if cmd == "" || cmd == "stats" || cmd == "status" {
		st := stats.GetStats()
		data, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			_, _ = conn.Write([]byte(`{"error": "failed to marshal stats"}`))
			return
		}
		_, _ = conn.Write(data)
		_, _ = conn.Write([]byte("\n"))
	} else if cmd == "health" {
		_, _ = conn.Write([]byte(`{"status":"ok"}` + "\n"))
	} else {
		_, _ = conn.Write([]byte(`{"error": "unknown command"}` + "\n"))
	}
}

type socketResponseWriter struct {
	conn       net.Conn
	header     http.Header
	wroteHeader bool
	status     int
}

func (w *socketResponseWriter) Header() http.Header {
	return w.header
}

func (w *socketResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = statusCode
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	for k, v := range w.header {
		for _, val := range v {
			fmt.Fprintf(w.conn, "%s: %s\r\n", k, val)
		}
	}
	fmt.Fprintf(w.conn, "\r\n")
}

func (w *socketResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(b)
}

func (e *Engine) Stop() {
	log.Printf("[Engine] Stopping service...")

	// 1. Signal context cancellation
	e.cancel()

	// 2. Shut down stats HTTP server and UNIX listener
	if e.statsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = e.statsServer.Shutdown(ctx)
	}
	if e.statsListener != nil {
		_ = e.statsListener.Close()
		if e.cfg.StatsSocket != "" {
			_ = os.Remove(e.cfg.StatsSocket)
		}
	}

	// 3. Stop all network/file listeners & close sockets
	for _, l := range e.listeners {
		if err := l.Stop(); err != nil {
			log.Printf("Error stopping listener %s: %v", l.Name(), err)
		}
	}

	// 4. Safely close msgChan so workers read remaining buffered messages and terminate
	close(e.msgChan)

	// 5. Wait for workers and stats routines to finish
	e.wg.Wait()

	// 6. Close Kafka producer connection
	if err := e.producer.Close(); err != nil {
		log.Printf("Error closing Kafka producer: %v", err)
	}

	log.Printf("[Engine] Shutdown complete.")
}
