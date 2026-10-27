package flow

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FlowParser provides a unified interface for parsing any flow datagram.
type FlowParser struct {
	cfg         *ParserConfig
	cache       *TemplateCache
	homeChecker *HomeNetChecker
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
	var subnets []string
	if cfg != nil {
		subnets = cfg.HomeNets
	}
	checker, _ := NewHomeNetChecker(subnets)

	cache := NewTemplateCache(ttl)
	loadAppDictionary(cache, cfg)

	return &FlowParser{
		cfg:         cfg,
		cache:       cache,
		homeChecker: checker,
	}
}

// NewFlowParserWithCache creates a FlowParser sharing an external TemplateCache.
func NewFlowParserWithCache(cfg *ParserConfig, cache *TemplateCache) *FlowParser {
	var subnets []string
	if cfg != nil {
		subnets = cfg.HomeNets
	}
	checker, _ := NewHomeNetChecker(subnets)
	loadAppDictionary(cache, cfg)

	return &FlowParser{
		cfg:         cfg,
		cache:       cache,
		homeChecker: checker,
	}
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

	if p.homeChecker != nil {
		for _, rec := range records {
			p.homeChecker.OrientFlow(rec)
		}
	}

	return records, nil
}
