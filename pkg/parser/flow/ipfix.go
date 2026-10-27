package flow

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ParseIPFIX parses an IPFIX (NetFlow v10) datagram using the template cache.
func ParseIPFIX(data []byte, exporterIP string, cache *TemplateCache, cfg *ParserConfig) ([]*JSONFlowRecord, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("ipfix packet too short: %d bytes (min 16)", len(data))
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 10 {
		return nil, fmt.Errorf("invalid ipfix version %d (expected 10)", version)
	}

	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen > len(data) {
		totalLen = len(data)
	}

	exportTime := int64(binary.BigEndian.Uint32(data[4:8]))
	flowSequence := binary.BigEndian.Uint32(data[8:12])
	domainID := binary.BigEndian.Uint32(data[12:16])

	var records []*JSONFlowRecord
	now := time.Now().Unix()
	offset := 16

	for offset+4 <= totalLen {
		setID := binary.BigEndian.Uint16(data[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if setLen < 4 {
			break
		}
		if offset+setLen > totalLen {
			break
		}

		setData := data[offset+4 : offset+setLen]
		offset += setLen

		switch {
		case setID == 2:
			// IPFIX Template Set
			tmplOffset := 0
			for tmplOffset+4 <= len(setData) {
				templateID := binary.BigEndian.Uint16(setData[tmplOffset : tmplOffset+2])
				fieldCount := int(binary.BigEndian.Uint16(setData[tmplOffset+2 : tmplOffset+4]))
				tmplOffset += 4

				var fields []FieldSpec
				for f := 0; f < fieldCount && tmplOffset+4 <= len(setData); f++ {
					elemID := binary.BigEndian.Uint16(setData[tmplOffset : tmplOffset+2])
					fieldLen := binary.BigEndian.Uint16(setData[tmplOffset+2 : tmplOffset+4])
					tmplOffset += 4

					var entNum uint32
					if elemID&0x8000 != 0 {
						// Enterprise bit set
						elemID &= 0x7FFF
						if tmplOffset+4 <= len(setData) {
							entNum = binary.BigEndian.Uint32(setData[tmplOffset : tmplOffset+4])
							tmplOffset += 4
						}
					}

					fields = append(fields, FieldSpec{
						TypeID:           elemID,
						Length:           fieldLen,
						EnterpriseNumber: entNum,
					})
				}

				if cache != nil {
					cache.Set(exporterIP, domainID, templateID, Template{
						TemplateID: templateID,
						Fields:     fields,
						LastSeen:   time.Now(),
					})
				}
			}

		case setID == 3:
			// IPFIX Options Template Set
			if len(setData) >= 6 {
				templateID := binary.BigEndian.Uint16(setData[0:2])
				fieldCount := int(binary.BigEndian.Uint16(setData[2:4]))
				scopeCount := int(binary.BigEndian.Uint16(setData[4:6]))
				_ = scopeCount
				tmplOffset := 6

				var fields []FieldSpec
				for f := 0; f < fieldCount && tmplOffset+4 <= len(setData); f++ {
					elemID := binary.BigEndian.Uint16(setData[tmplOffset : tmplOffset+2])
					fieldLen := binary.BigEndian.Uint16(setData[tmplOffset+2 : tmplOffset+4])
					tmplOffset += 4

					var entNum uint32
					if elemID&0x8000 != 0 {
						elemID &= 0x7FFF
						if tmplOffset+4 <= len(setData) {
							entNum = binary.BigEndian.Uint32(setData[tmplOffset : tmplOffset+4])
							tmplOffset += 4
						}
					}
					fields = append(fields, FieldSpec{
						TypeID:           elemID,
						Length:           fieldLen,
						EnterpriseNumber: entNum,
					})
				}

				if cache != nil {
					cache.Set(exporterIP, domainID, templateID, Template{
						TemplateID:       templateID,
						Fields:           fields,
						LastSeen:         time.Now(),
						IsOptionTemplate: true,
					})
				}
			}

		case setID >= 256:
			// Data Set: setID is TemplateID
			if cache == nil {
				continue
			}
			tmpl, ok := cache.Get(exporterIP, domainID, setID)
			if !ok {
				continue
			}

			if tmpl.IsOptionTemplate {
				// Process Option Data Set: learn metadata mappings without emitting traffic records
				dataOffset := 0
				for dataOffset < len(setData) {
					var appID uint64
					var appName string
					var ifIndex uint32
					var ifName string
					hasAppID := false
					hasIfIndex := false
					recordValid := true
					startOffset := dataOffset

					for _, f := range tmpl.Fields {
						var val []byte
						if f.Length == 0xFFFF {
							if dataOffset >= len(setData) {
								recordValid = false
								break
							}
							varLen := int(setData[dataOffset])
							dataOffset++
							if varLen == 255 {
								if dataOffset+2 > len(setData) {
									recordValid = false
									break
								}
								varLen = int(binary.BigEndian.Uint16(setData[dataOffset : dataOffset+2]))
								dataOffset += 2
							}
							if dataOffset+varLen > len(setData) {
								recordValid = false
								break
							}
							val = setData[dataOffset : dataOffset+varLen]
							dataOffset += varLen
						} else {
							fLen := int(f.Length)
							if dataOffset+fLen > len(setData) {
								recordValid = false
								break
							}
							val = setData[dataOffset : dataOffset+fLen]
							dataOffset += fLen
						}

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

					if !recordValid || dataOffset == startOffset {
						break
					}

					if hasAppID && appName != "" {
						cache.SetAppName(exporterIP, domainID, appID, appName)
						if appID > 0xFFFFFFFF {
							cache.SetAppName(exporterIP, domainID, uint64(uint32(appID)), appName)
						}
					}
					if hasIfIndex && ifName != "" {
						cache.SetIfName(exporterIP, domainID, ifIndex, ifName)
					}
				}
				continue
			}

			dataOffset := 0
			for dataOffset < len(setData) {
				rec := &JSONFlowRecord{
					Type:                "netflowv10",
					FlowSequence:        fmt.Sprintf("%d", flowSequence),
					ObservationDomainID: &domainID,
					IPProtocolVersion:   4,
					Timestamp:           now,
					StartTime:           exportTime,
					EndTime:             exportTime,
					SensorIP:            exporterIP,
				}

				spanPort := false
				if cfg != nil {
					spanPort = cfg.SpanPort
				}

				recordValid := true
				startOffset := dataOffset

				for _, f := range tmpl.Fields {
					var val []byte
					if f.Length == 0xFFFF {
						// Variable length field (RFC 7011 Section 7)
						if dataOffset >= len(setData) {
							recordValid = false
							break
						}
						varLen := int(setData[dataOffset])
						dataOffset++
						if varLen == 255 {
							if dataOffset+2 > len(setData) {
								recordValid = false
								break
							}
							varLen = int(binary.BigEndian.Uint16(setData[dataOffset : dataOffset+2]))
							dataOffset += 2
						}
						if dataOffset+varLen > len(setData) {
							recordValid = false
							break
						}
						val = setData[dataOffset : dataOffset+varLen]
						dataOffset += varLen
					} else {
						// Fixed length field
						fLen := int(f.Length)
						if dataOffset+fLen > len(setData) {
							recordValid = false
							break
						}
						val = setData[dataOffset : dataOffset+fLen]
						dataOffset += fLen
					}

					applyFieldToRecord(rec, f, val, spanPort, cache)
				}

				if !recordValid {
					break
				}

				// If no bytes were consumed, avoid infinite loop
				if dataOffset == startOffset {
					break
				}

				records = append(records, rec)
			}
		}
	}

	return records, nil
}
