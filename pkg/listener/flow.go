package listener

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"x2kafka/pkg/config"
	"x2kafka/pkg/decoder"
	"x2kafka/pkg/kafka"
	"x2kafka/pkg/parser/flow"
	"x2kafka/pkg/security"
	"x2kafka/pkg/stats"
)

// FlowListener receives NetFlow v5, NetFlow v9, IPFIX, and sFlow packets over UDP.
type FlowListener struct {
	cfg      config.ListenerConfig
	decoder  *decoder.Decoder
	ipFilter *security.IPFilter
	parser   *flow.FlowParser
	udpConn  *net.UDPConn
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewFlowListener creates a new FlowListener instance.
func NewFlowListener(cfg config.ListenerConfig) *FlowListener {
	if cfg.Port == 0 {
		if cfg.Proto == "sflow" || cfg.Proto == "sflow_udp" {
			cfg.Port = 6343
		} else {
			cfg.Port = 2055
		}
	}
	if cfg.Topic == "" {
		cfg.Topic = "rb_flow"
	}
	if cfg.Bind == "" {
		cfg.Bind = "0.0.0.0"
	}
	if cfg.MaxMsgSize == 0 {
		cfg.MaxMsgSize = 65536
	}

	renormalize := true
	if cfg.RenormalizeSampling != nil {
		renormalize = *cfg.RenormalizeSampling
	}

	ttl := 30 * time.Minute
	if cfg.TemplateTTLSeconds > 0 {
		ttl = time.Duration(cfg.TemplateTTLSeconds) * time.Second
	}

	homeNets := cfg.HomeNets
	if len(homeNets) == 0 && len(cfg.HomeNet) > 0 {
		homeNets = cfg.HomeNet
	}

	pCfg := &flow.ParserConfig{
		TemplateTTL:         ttl,
		RenormalizeSampling: renormalize,
		ExcludeFields:       cfg.ExcludeFields,
		HomeNets:            homeNets,
		SpanPort:            cfg.SpanPort,
		ApplicationsFile:    cfg.ApplicationsFile,
		HostsPath:           cfg.HostsPath,
	}

	return &FlowListener{
		cfg:      cfg,
		decoder:  decoder.NewDecoder(),
		ipFilter: security.NewIPFilter(cfg.AllowedIPs, cfg.BlacklistIPs),
		parser:   flow.NewFlowParser(pCfg),
	}
}

// Name returns the listener identifier.
func (f *FlowListener) Name() string {
	if f.cfg.Name != "" {
		return f.cfg.Name
	}
	return fmt.Sprintf("flow-%s-%d", f.cfg.Proto, f.cfg.Port)
}

// Start begins listening on the configured UDP port.
func (f *FlowListener) Start(ctx context.Context, msgChan chan<- *kafka.Message) error {
	f.ctx, f.cancel = context.WithCancel(ctx)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", f.cfg.Bind, f.cfg.Port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s:%d: %w", f.cfg.Bind, f.cfg.Port, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", addr.String(), err)
	}
	f.udpConn = conn

	if f.cfg.SocketBufferBytes > 0 {
		if err := conn.SetReadBuffer(f.cfg.SocketBufferBytes); err != nil {
			log.Printf("[%s] Warning: unable to set socket buffer size to %d: %v", f.Name(), f.cfg.SocketBufferBytes, err)
		}
	}

	f.wg.Add(1)
	go f.listenLoop(msgChan)

	log.Printf("[%s] Flow listener started on %s (proto: %s, topic: %s)", f.Name(), addr.String(), f.cfg.Proto, f.cfg.Topic)
	return nil
}

func (f *FlowListener) listenLoop(msgChan chan<- *kafka.Message) {
	defer f.wg.Done()

	buf := make([]byte, f.cfg.MaxMsgSize)

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		_ = f.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := f.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-f.ctx.Done():
				return
			default:
				stats.IncListenerError(f.Name())
				continue
			}
		}

		remoteIP := remoteAddr.IP.String()
		if !f.ipFilter.IsAllowed(remoteIP) {
			continue
		}

		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		records, err := f.parser.Parse(packetData, remoteIP)
		if err != nil {
			stats.IncListenerError(f.Name())
			continue
		}

		for _, rec := range records {
			// Populate SensorIP if empty
			if rec.SensorIP == "" {
				rec.SensorIP = remoteIP
			}

			// Apply per-sensor enrichment map if key matches (sensor_ip, exporter_ip, or observation_id)
			if f.cfg.EnrichmentMap != nil {
				var matchedFields map[string]interface{}

				// 1. Check <remoteIP>:<observation_id> (e.g. "10.1.50.20:100")
				if rec.ObservationDomainID != nil {
					obsKey := fmt.Sprintf("%s:%d", remoteIP, *rec.ObservationDomainID)
					if fields, ok := f.cfg.EnrichmentMap[obsKey]; ok {
						matchedFields = fields
					}
				}

				// 2. Check remoteIP, rec.SensorIP, or custom enrichment key
				if matchedFields == nil {
					keyVal := remoteIP
					if (f.cfg.EnrichmentKey == "sensor_ip" || f.cfg.EnrichmentKey == "") && rec.SensorIP != "" {
						keyVal = rec.SensorIP
					} else if f.cfg.EnrichmentKey == "lan_ip" && rec.LanIP != "" {
						keyVal = rec.LanIP
					}
					if fields, ok := f.cfg.EnrichmentMap[keyVal]; ok {
						matchedFields = fields
					} else if fields, ok := f.cfg.EnrichmentMap[remoteIP]; ok {
						matchedFields = fields
					}
				}

				// 3. Fallback to "default" entry if configured
				if matchedFields == nil {
					if fields, ok := f.cfg.EnrichmentMap["default"]; ok {
						matchedFields = fields
					}
				}

				if matchedFields != nil {
					// Check for nested "observations_id" map matching f2k Chef cookbook structure
					if obsMapRaw, ok := matchedFields["observations_id"].(map[string]interface{}); ok && rec.ObservationDomainID != nil {
						obsStr := fmt.Sprintf("%d", *rec.ObservationDomainID)
						if specificRaw, ok := obsMapRaw[obsStr].(map[string]interface{}); ok {
							if enrichMap, ok := specificRaw["enrichment"].(map[string]interface{}); ok {
								matchedFields = enrichMap
							} else {
								matchedFields = specificRaw
							}
						} else if defRaw, ok := obsMapRaw["default"].(map[string]interface{}); ok {
							if enrichMap, ok := defRaw["enrichment"].(map[string]interface{}); ok {
								matchedFields = enrichMap
							} else {
								matchedFields = defRaw
							}
						}
					}

					if uuid, ok := matchedFields["sensor_uuid"].(string); ok {
						rec.SensorUUID = uuid
					}
					if name, ok := matchedFields["sensor_name"].(string); ok {
						rec.SensorName = name
					}
				}
			}

			filteredJSON, err := rec.ToFilteredJSON(f.cfg.ExcludeFields)
			if err != nil {
				stats.IncListenerError(f.Name())
				continue
			}

			formatted, targetTopic, err := f.decoder.FormatPayloadWithConfigAndTopic(filteredJSON, f.cfg, "", "")
			if err != nil {
				stats.IncListenerError(f.Name())
				continue
			}

			topic := targetTopic
			if topic == "" {
				topic = f.cfg.Topic
			}

			msg := &kafka.Message{
				Topic:     topic,
				Value:     formatted,
				Timestamp: time.Unix(rec.Timestamp, 0),
			}

			select {
			case msgChan <- msg:
				stats.IncMessagesReceived(f.Name(), len(formatted))
			case <-f.ctx.Done():
				return
			}
		}
	}
}

// Stop stops the flow listener and closes the UDP socket.
func (f *FlowListener) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	if f.udpConn != nil {
		_ = f.udpConn.Close()
	}
	f.wg.Wait()
	log.Printf("[%s] Flow listener stopped", f.Name())
	return nil
}
