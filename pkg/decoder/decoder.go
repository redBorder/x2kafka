package decoder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"x2kafka/pkg/config"
	"x2kafka/pkg/parser"
)

type Decoder struct{}

func NewDecoder() *Decoder {
	return &Decoder{}
}

// FormatPayloadWithConfigAndTopic formats raw data applying both static and dynamic key-based enrichment rules, returning the enriched payload and any per-rule topic override.
func (d *Decoder) FormatPayloadWithConfigAndTopic(raw []byte, cfg config.ListenerConfig, sourceProto string, sourceAddr string) ([]byte, string, error) {
	rawTrimmed := bytes.TrimSpace(raw)
	if len(rawTrimmed) == 0 {
		return nil, "", nil
	}

	mode := cfg.Mode
	if mode == "raw" && len(cfg.Enrichment) == 0 && len(cfg.EnrichmentMap) == 0 && len(cfg.EnrichmentRules) == 0 {
		return rawTrimmed, "", nil
	}

	var doc map[string]interface{}
	if isJSON(rawTrimmed) {
		err := json.Unmarshal(rawTrimmed, &doc)
		if err != nil {
			doc = make(map[string]interface{})
			doc["payload"] = string(rawTrimmed)
		}
	} else {
		doc = make(map[string]interface{})
		doc["payload"] = string(rawTrimmed)
	}

	// Add timestamp and source metadata if missing
	if _, ok := doc["timestamp"]; !ok {
		doc["timestamp"] = time.Now().Unix()
	}
	if _, ok := doc["source_proto"]; !ok && sourceProto != "" {
		doc["source_proto"] = sourceProto
	}
	if _, ok := doc["source_addr"]; !ok && sourceAddr != "" {
		doc["source_addr"] = sourceAddr
	}

	// Message field extraction & parsing pipeline (KV, CEF, Regex, Schema Standardization)
	var rawMsgText string
	if msgVal, ok := doc["message"]; ok {
		rawMsgText = fmt.Sprintf("%v", msgVal)
	} else if rawVal, ok := doc["raw_message"]; ok {
		rawMsgText = fmt.Sprintf("%v", rawVal)
	} else if payloadVal, ok := doc["payload"]; ok {
		rawMsgText = fmt.Sprintf("%v", payloadVal)
	}

	if rawMsgText != "" {
		extracted := make(map[string]interface{})

		if cfg.CEFExtract {
			if cefFields, ok := parser.ParseCEF(rawMsgText); ok {
				for k, v := range cefFields {
					extracted[k] = v
				}
			}
		}

		if cfg.KVExtract {
			kvFields := parser.ParseKV(rawMsgText)
			for k, v := range kvFields {
				extracted[k] = v
			}
		}

		if len(cfg.RegexPatterns) > 0 {
			if p, err := parser.NewDecoderParser(cfg.RegexPatterns); err == nil {
				regexFields := p.ParseRegex(rawMsgText)
				for k, v := range regexFields {
					extracted[k] = v
				}
			}
		}

		if cfg.SchemaStandardization && len(extracted) > 0 {
			extracted = parser.NormalizeSchema(extracted)
		}

		for k, v := range extracted {
			if _, exists := doc[k]; !exists {
				doc[k] = v
			}
		}
	}

	// 1. Apply default static enrichment
	for k, v := range cfg.Enrichment {
		doc[k] = v
	}

	// 2. Perform dynamic key-based enrichment lookup
	keyName := cfg.EnrichmentKey
	if keyName == "" {
		keyName = "sensor_uuid"
	}

	keyValueStr := ""
	if val, ok := doc[keyName]; ok && val != nil {
		keyValueStr = fmt.Sprintf("%v", val)
	} else if keyName == "src_ip" || keyName == "fromhost_ip" || keyName == "source_addr" {
		keyValueStr = sourceAddr
	}

	targetTopic := ""

	// A. Check EnrichmentMap[keyValueStr]
	if keyValueStr != "" && len(cfg.EnrichmentMap) > 0 {
		if mappedEnrichment, ok := cfg.EnrichmentMap[keyValueStr]; ok {
			for k, v := range mappedEnrichment {
				// home_nets only orient the flows of the sensor, they are not part of the event
				if k == "home_nets" {
					continue
				}
				doc[k] = v
			}
		}
	}

	// B. Check EnrichmentRules list
	if len(cfg.EnrichmentRules) > 0 {
		for _, rule := range cfg.EnrichmentRules {
			matched := true

			// Multi-field match check (match_fields)
			if len(rule.MatchFields) > 0 {
				for targetKey, expectedVal := range rule.MatchFields {
					valToCheck := ""
					if v, ok := doc[targetKey]; ok && v != nil {
						valToCheck = fmt.Sprintf("%v", v)
					} else if targetKey == "src_ip" || targetKey == "fromhost_ip" || targetKey == "source_addr" {
						valToCheck = sourceAddr
					}

					if valToCheck != expectedVal {
						matched = false
						break
					}
				}
			}

			// Single-field value match check (legacy match_key / match_value)
			if matched && rule.MatchValue != "" {
				targetKey := rule.MatchKey
				if targetKey == "" {
					targetKey = keyName
				}

				valToCheck := ""
				if v, ok := doc[targetKey]; ok && v != nil {
					valToCheck = fmt.Sprintf("%v", v)
				} else if targetKey == "src_ip" || targetKey == "fromhost_ip" || targetKey == "source_addr" {
					valToCheck = sourceAddr
				}

				if valToCheck != rule.MatchValue {
					matched = false
				}
			}

			// Substring contains check
			if matched && len(rule.Contains) > 0 {
				fullText := string(rawTrimmed)
				if rawMsgVal, ok := doc["raw_message"]; ok {
					fullText = fmt.Sprintf("%v", rawMsgVal)
				} else if msgVal, ok := doc["message"]; ok {
					fullText = fmt.Sprintf("%v", msgVal)
				}

				for _, substr := range rule.Contains {
					if !strings.Contains(fullText, substr) {
						matched = false
						break
					}
				}
			}

			if matched {
				for k, v := range rule.Enrichment {
					doc[k] = v
				}
				if rule.Topic != "" {
					targetTopic = rule.Topic
				}
			}
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return rawTrimmed, targetTopic, nil
	}

	return bytes.TrimSpace(buf.Bytes()), targetTopic, nil
}

func (d *Decoder) FormatPayloadWithConfig(raw []byte, cfg config.ListenerConfig, sourceProto string, sourceAddr string) ([]byte, error) {
	out, _, err := d.FormatPayloadWithConfigAndTopic(raw, cfg, sourceProto, sourceAddr)
	return out, err
}

func (d *Decoder) FormatPayload(raw []byte, mode string, enrichment map[string]interface{}, sourceProto string, sourceAddr string) ([]byte, error) {
	cfg := config.ListenerConfig{
		Mode:       mode,
		Enrichment: enrichment,
	}
	return d.FormatPayloadWithConfig(raw, cfg, sourceProto, sourceAddr)
}

func isJSON(b []byte) bool {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return false
	}
	return (b[0] == '{' && b[len(b)-1] == '}') || (b[0] == '[' && b[len(b)-1] == ']')
}
