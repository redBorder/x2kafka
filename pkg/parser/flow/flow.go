package flow

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// FlowParser provides a unified interface for parsing any flow datagram.
type FlowParser struct {
	cfg         *ParserConfig
	cache       *TemplateCache
	homeChecker *HomeNetChecker
	sensorHome  map[string]*HomeNetChecker // per sensor checkers, they win over homeChecker
	ndpi        AppClassifier              // nil unless nDPI was requested and is compiled in
	appCache    *serverAppCache            // nDPI detections remembered per server endpoint
}

func newFlowParser(cfg *ParserConfig, cache *TemplateCache) *FlowParser {
	var subnets []string
	if cfg != nil {
		subnets = cfg.HomeNets
	}
	checker, _ := NewHomeNetChecker(subnets)
	loadAppDictionary(cache, cfg)

	p := &FlowParser{
		cfg:         cfg,
		cache:       cache,
		homeChecker: checker,
		sensorHome:  newSensorHomeCheckers(cfg),
	}
	if cfg != nil && cfg.NDPI {
		classifier, err := NewNDPIClassifier()
		if err != nil {
			log.Printf("[flow] nDPI requested but not available, sFlow applications fall back to port mapping: %v", err)
		} else {
			p.ndpi = classifier
			p.appCache = newServerAppCache(cfg.NDPICacheTTL)
		}
	}
	return p
}

// newSensorHomeCheckers builds one HomeNetChecker per sensor with its own home_nets.
// A sensor with an invalid CIDR keeps the listener home_nets instead of losing the orientation.
func newSensorHomeCheckers(cfg *ParserConfig) map[string]*HomeNetChecker {
	if cfg == nil || len(cfg.SensorHomeNets) == 0 {
		return nil
	}
	checkers := make(map[string]*HomeNetChecker, len(cfg.SensorHomeNets))
	for key, subnets := range cfg.SensorHomeNets {
		if len(subnets) == 0 {
			continue
		}
		checker, err := NewHomeNetChecker(subnets)
		if err != nil {
			log.Printf("[flow] ignoring home_nets of sensor %s, using the listener ones: %v", key, err)
			continue
		}
		checkers[key] = checker
	}
	return checkers
}

// homeCheckerFor returns the home_nets checker of the sensor that exported rec, looked up
// like the enrichment_map (exporter:observation_id, sensor IP, exporter IP, "default").
// Falls back to the listener home_nets when the sensor has none of its own.
func (p *FlowParser) homeCheckerFor(rec *JSONFlowRecord, exporterIP string) *HomeNetChecker {
	if len(p.sensorHome) > 0 {
		if rec.ObservationDomainID != nil {
			if c, ok := p.sensorHome[fmt.Sprintf("%s:%d", exporterIP, *rec.ObservationDomainID)]; ok {
				return c
			}
		}
		if rec.SensorIP != "" {
			if c, ok := p.sensorHome[rec.SensorIP]; ok {
				return c
			}
		}
		if c, ok := p.sensorHome[exporterIP]; ok {
			return c
		}
		if c, ok := p.sensorHome["default"]; ok {
			return c
		}
	}
	return p.homeChecker
}

// Close releases the nDPI detection module, if any. The parser must not be used afterwards.
func (p *FlowParser) Close() {
	if p.ndpi != nil {
		p.ndpi.Close()
		p.ndpi = nil
	}
}

func loadAppDictionary(cache *TemplateCache, cfg *ParserConfig) {
	if cache == nil || cfg == nil {
		return
	}
	appFile := cfg.ApplicationsFile
	if appFile == "" && cfg.HostsPath != "" {
		candidate := filepath.Join(cfg.HostsPath, "applications")
		if _, err := os.Stat(candidate); err == nil {
			appFile = candidate
		}
	}
	if appFile == "" {
		// Auto-check standard redBorder applications database locations
		for _, candidate := range []string{
			"/etc/objects/applications",
			"/opt/rb/etc/objects/applications",
		} {
			if _, err := os.Stat(candidate); err == nil {
				appFile = candidate
				break
			}
		}
	}
	if appFile != "" {
		_ = cache.LoadApplicationDictionary(appFile)
	}
}

// NewFlowParser creates a new FlowParser with default cache TTL.
func NewFlowParser(cfg *ParserConfig) *FlowParser {
	ttl := 30 * time.Minute
	if cfg != nil && cfg.TemplateTTL > 0 {
		ttl = cfg.TemplateTTL
	}
	return newFlowParser(cfg, NewTemplateCache(ttl))
}

// NewFlowParserWithCache creates a FlowParser sharing an external TemplateCache.
func NewFlowParserWithCache(cfg *ParserConfig, cache *TemplateCache) *FlowParser {
	return newFlowParser(cfg, cache)
}

// Parse auto-detects the flow protocol and parses the datagram.
func (p *FlowParser) Parse(data []byte, exporterIP string) ([]*JSONFlowRecord, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short: %d bytes (min 4)", len(data))
	}

	var records []*JSONFlowRecord
	var err error

	// Check 4-byte big-endian version first (sFlow v5 uses uint32 version = 5)
	ver32 := binary.BigEndian.Uint32(data[0:4])
	if ver32 == 5 && len(data) >= 28 && binary.BigEndian.Uint16(data[0:2]) == 0 && binary.BigEndian.Uint16(data[2:4]) == 5 {
		records, err = ParseSFlow(data, exporterIP, p.cfg)
		// Classify before the home_nets orientation swaps source and destination.
		for _, rec := range records {
			p.classifySFlow(rec)
			rec.l3 = nil
		}
	} else {
		// 2-byte big-endian version (NetFlow / IPFIX)
		ver16 := binary.BigEndian.Uint16(data[0:2])
		switch ver16 {
		case 5:
			records, err = ParseNetFlowV5(data, exporterIP, p.cfg)
		case 9:
			records, err = ParseNetFlowV9(data, exporterIP, p.cache, p.cfg)
		case 10:
			records, err = ParseIPFIX(data, exporterIP, p.cache, p.cfg)
		default:
			return nil, fmt.Errorf("unsupported flow protocol version 0x%04x", ver16)
		}
	}

	if err != nil {
		return nil, err
	}

	for _, rec := range records {
		p.homeCheckerFor(rec, exporterIP).OrientFlow(rec)
	}

	return records, nil
}
