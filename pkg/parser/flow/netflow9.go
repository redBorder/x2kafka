package flow

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ParseNetFlowV9 parses a NetFlow v9 datagram using the template cache.
func ParseNetFlowV9(data []byte, exporterIP string, cache *TemplateCache, cfg *ParserConfig) ([]*JSONFlowRecord, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("netflow v9 packet too short: %d bytes (min 20)", len(data))
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 9 {
		return nil, fmt.Errorf("invalid netflow version %d (expected 9)", version)
	}

	sysUptime := binary.BigEndian.Uint32(data[4:8])
	unixSecs := int64(binary.BigEndian.Uint32(data[8:12]))
	flowSequence := binary.BigEndian.Uint32(data[12:16])
	sourceID := binary.BigEndian.Uint32(data[16:20])

	var records []*JSONFlowRecord
	now := time.Now().Unix()
	offset := 20

	for offset+4 <= len(data) {
		flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
		flowSetLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if flowSetLen < 4 {
			break
		}
		if offset+flowSetLen > len(data) {
			break
		}

		flowSetData := data[offset+4 : offset+flowSetLen]
		offset += flowSetLen

		switch {
		case flowSetID == 0:
			// Template FlowSet
			tmplOffset := 0
			for tmplOffset+4 <= len(flowSetData) {
				templateID := binary.BigEndian.Uint16(flowSetData[tmplOffset : tmplOffset+2])
				fieldCount := int(binary.BigEndian.Uint16(flowSetData[tmplOffset+2 : tmplOffset+4]))
				tmplOffset += 4

				if tmplOffset+fieldCount*4 > len(flowSetData) {
					break
				}

				fields := make([]FieldSpec, fieldCount)
				for f := 0; f < fieldCount; f++ {
					typeID := binary.BigEndian.Uint16(flowSetData[tmplOffset : tmplOffset+2])
					fieldLen := binary.BigEndian.Uint16(flowSetData[tmplOffset+2 : tmplOffset+4])
					tmplOffset += 4
					fields[f] = FieldSpec{
						TypeID: typeID,
						Length: fieldLen,
					}
				}

				if cache != nil {
					cache.Set(exporterIP, sourceID, templateID, Template{
						TemplateID: templateID,
						Fields:     fields,
						LastSeen:   time.Now(),
					})
				}
			}

		case flowSetID == 1:
			// Options Template FlowSet
			if len(flowSetData) >= 6 {
				templateID := binary.BigEndian.Uint16(flowSetData[0:2])
				scopeLen := int(binary.BigEndian.Uint16(flowSetData[2:4]))
				optLen := int(binary.BigEndian.Uint16(flowSetData[4:6]))
				totalLen := scopeLen + optLen
				if 6+totalLen <= len(flowSetData) {
					optOffset := 6
					var fields []FieldSpec
					for optOffset+4 <= 6+totalLen {
						tID := binary.BigEndian.Uint16(flowSetData[optOffset : optOffset+2])
						fLen := binary.BigEndian.Uint16(flowSetData[optOffset+2 : optOffset+4])
						optOffset += 4
						fields = append(fields, FieldSpec{TypeID: tID, Length: fLen})
					}
					if cache != nil {
						cache.Set(exporterIP, sourceID, templateID, Template{
							TemplateID:       templateID,
							Fields:           fields,
							LastSeen:         time.Now(),
							IsOptionTemplate: true,
						})
					}
				}
			}

		case flowSetID >= 256:
			// Data FlowSet: flowSetID is the Template ID
			if cache == nil {
				continue
			}
			tmpl, ok := cache.Get(exporterIP, sourceID, flowSetID)
			if !ok {
				// Unknown template, cannot parse without schema
				continue
			}

			// Calculate record length
			recordLen := 0
			for _, f := range tmpl.Fields {
				recordLen += int(f.Length)
			}
			if recordLen <= 0 {
				continue
			}

			if tmpl.IsOptionTemplate {
				// Process Option Data FlowSet: learn metadata mappings without emitting traffic records
				dataOffset := 0
				for dataOffset+recordLen <= len(flowSetData) {
					recBytes := flowSetData[dataOffset : dataOffset+recordLen]
					dataOffset += recordLen

					var appID uint64
					var appName string
					var ifIndex uint32
					var ifName string
					hasAppID := false
					hasIfIndex := false

					fieldOffset := 0
					for _, f := range tmpl.Fields {
						fLen := int(f.Length)
						if fieldOffset+fLen > len(recBytes) {
							break
						}
						val := recBytes[fieldOffset : fieldOffset+fLen]
						fieldOffset += fLen

						switch f.TypeID {
						case IE_APPLICATION_ID:
							appID = decodeUint(val)
							hasAppID = true
						case IE_APPLICATION_NAME:
							appName = strings.TrimRight(string(val), "\x00")
						case IE_INGRESS_INTERFACE, IE_EGRESS_INTERFACE:
							ifIndex = uint32(decodeUint(val))
							hasIfIndex = true
						case IE_IF_NAME, IE_IF_DESCRIPTION:
							ifName = strings.TrimRight(string(val), "\x00")
						}
					}

					if hasAppID && appName != "" {
						cache.SetAppName(exporterIP, sourceID, appID, appName)
						if appID > 0xFFFFFFFF {
							cache.SetAppName(exporterIP, sourceID, uint64(uint32(appID)), appName)
						}
					}
					if hasIfIndex && ifName != "" {
						cache.SetIfName(exporterIP, sourceID, ifIndex, ifName)
					}
				}
				continue
			}

			dataOffset := 0
			for dataOffset+recordLen <= len(flowSetData) {
				recBytes := flowSetData[dataOffset : dataOffset+recordLen]
				dataOffset += recordLen

				rec := &JSONFlowRecord{
					Type:                "netflowv9",
					FlowSequence:        fmt.Sprintf("%d", flowSequence),
					ObservationDomainID: &sourceID,
					IPProtocolVersion:   4,
					Timestamp:           now,
					SensorIP:            exporterIP,
				}

				spanPort := false
				if cfg != nil {
					spanPort = cfg.SpanPort
				}

				fieldOffset := 0
				for _, f := range tmpl.Fields {
					fLen := int(f.Length)
					val := recBytes[fieldOffset : fieldOffset+fLen]
					fieldOffset += fLen
					applyFieldToRecord(rec, f, val, spanPort, cache)
				}

				if rec.StartTime == 0 && rec.EndTime == 0 {
					rec.StartTime = unixSecs
					rec.EndTime = unixSecs
				} else if rec.StartTime > 0 && sysUptime > 0 && rec.StartTime < 1000000000 {
					// Timestamps were uptime offsets (FIRST_SWITCHED / LAST_SWITCHED)
					firstUptime := uint32(rec.StartTime)
					lastUptime := uint32(rec.EndTime)
					if sysUptime >= firstUptime {
						rec.StartTime = unixSecs - int64((sysUptime-firstUptime)/1000)
					}
					if sysUptime >= lastUptime {
						rec.EndTime = unixSecs - int64((sysUptime-lastUptime)/1000)
					}
					if lastUptime >= firstUptime {
						rec.Duration = int64(lastUptime - firstUptime)
					}
				}

				records = append(records, rec)
			}
		}
	}

	return records, nil
}
