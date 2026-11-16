package flow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ParseSFlow parses an sFlow v5 datagram into JSONFlowRecord slices.
func ParseSFlow(data []byte, exporterIP string, cfg *ParserConfig) ([]*JSONFlowRecord, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("sflow packet too short: %d bytes (min 28)", len(data))
	}

	version := binary.BigEndian.Uint32(data[0:4])
	if version != 5 {
		return nil, fmt.Errorf("invalid sflow version %d (expected 5)", version)
	}

	addrType := binary.BigEndian.Uint32(data[4:8])
	offset := 8

	var agentIP string
	if addrType == 1 {
		// IPv4
		if offset+4 > len(data) {
			return nil, fmt.Errorf("sflow truncated agent ipv4")
		}
		agentIP = net.IP(data[offset : offset+4]).String()
		offset += 4
	} else if addrType == 2 {
		// IPv6
		if offset+16 > len(data) {
			return nil, fmt.Errorf("sflow truncated agent ipv6")
		}
		agentIP = net.IP(data[offset : offset+16]).String()
		offset += 16
	} else {
		return nil, fmt.Errorf("unsupported sflow agent address type %d", addrType)
	}

	if offset+16 > len(data) {
		return nil, fmt.Errorf("sflow header truncated after agent address")
	}

	// subAgentID := binary.BigEndian.Uint32(data[offset : offset+4])
	// seqNum := binary.BigEndian.Uint32(data[offset+4 : offset+8])
	// uptime := binary.BigEndian.Uint32(data[offset+8 : offset+12])
	numSamples := int(binary.BigEndian.Uint32(data[offset+12 : offset+16]))
	offset += 16

	var records []*JSONFlowRecord
	now := time.Now().Unix()

	for s := 0; s < numSamples && offset+8 <= len(data); s++ {
		sampleTypeRaw := binary.BigEndian.Uint32(data[offset : offset+4])
		sampleLen := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
		offset += 8

		if offset+sampleLen > len(data) {
			break
		}

		sampleData := data[offset : offset+sampleLen]
		offset += sampleLen

		enterprise := sampleTypeRaw >> 12
		format := sampleTypeRaw & 0x0FFF

		if enterprise != 0 {
			// Not standard sFlow format
			continue
		}

		// Handle Flow Sample (Format 1) and Expanded Flow Sample (Format 3)
		var samplingRate, numRecords uint32
		var sampleOffset int

		if format == 1 {
			// Flow Sample
			if len(sampleData) < 32 {
				continue
			}
			// seq := binary.BigEndian.Uint32(sampleData[0:4])
			// sourceID := binary.BigEndian.Uint32(sampleData[4:8])
			samplingRate = binary.BigEndian.Uint32(sampleData[8:12])
			// samplePool := binary.BigEndian.Uint32(sampleData[12:16])
			// drops := binary.BigEndian.Uint32(sampleData[16:20])
			// inputIf := binary.BigEndian.Uint32(sampleData[20:24])
			// outputIf := binary.BigEndian.Uint32(sampleData[24:28])
			numRecords = binary.BigEndian.Uint32(sampleData[28:32])
			sampleOffset = 32
		} else if format == 3 {
			// Expanded Flow Sample
			if len(sampleData) < 44 {
				continue
			}
			samplingRate = binary.BigEndian.Uint32(sampleData[12:16])
			numRecords = binary.BigEndian.Uint32(sampleData[40:44])
			sampleOffset = 44
		} else {
			// Counter Sample (Format 2 / 4) or other
			continue
		}

		for r := 0; r < int(numRecords) && sampleOffset+8 <= len(sampleData); r++ {
			recTypeRaw := binary.BigEndian.Uint32(sampleData[sampleOffset : sampleOffset+4])
			recLen := int(binary.BigEndian.Uint32(sampleData[sampleOffset+4 : sampleOffset+8]))
			sampleOffset += 8

			if sampleOffset+recLen > len(sampleData) {
				break
			}

			recData := sampleData[sampleOffset : sampleOffset+recLen]
			sampleOffset += recLen

			recEnterprise := recTypeRaw >> 12
			recFormat := recTypeRaw & 0x0FFF

			if recEnterprise == 0 && recFormat == 1 {
				// Raw Packet Header (Flow Record Format 1)
				if len(recData) < 16 {
					continue
				}

				headerProto := binary.BigEndian.Uint32(recData[0:4])
				frameLen := binary.BigEndian.Uint32(recData[4:8])
				// stripped := binary.BigEndian.Uint32(recData[8:12])
				headerLen := int(binary.BigEndian.Uint32(recData[12:16]))

				if 16+headerLen > len(recData) {
					headerLen = len(recData) - 16
				}
				packetBytes := recData[16 : 16+headerLen]

				rec := &JSONFlowRecord{
					Type:              "sflow",
					IPProtocolVersion: 4,
					SamplingRate:      samplingRate,
					Timestamp:         now,
					StartTime:         now,
					EndTime:           now,
					SensorIP:          agentIP,
				}
				if rec.SensorIP == "" {
					rec.SensorIP = exporterIP
				}

				pkts := uint64(1)
				bytesCount := uint64(frameLen)
				if cfg != nil && cfg.RenormalizeSampling && samplingRate > 1 {
					pkts *= uint64(samplingRate)
					bytesCount *= uint64(samplingRate)
				}
				rec.Pkts = pkts
				rec.Bytes = bytesCount

				if headerProto == 1 {
					// Ethernet ISO 8802-3
					dissectEthernet(packetBytes, rec)
				} else if headerProto == 11 {
					// IPv4
					dissectIPv4(packetBytes, rec)
				} else if headerProto == 12 {
					// IPv6
					dissectIPv6(packetBytes, rec)
				}

				records = append(records, rec)
			}
		}
	}

	return records, nil
}

func dissectEthernet(b []byte, rec *JSONFlowRecord) {
	if len(b) < 14 {
		return
	}

	rec.ServerMAC = net.HardwareAddr(b[0:6]).String()
	rec.ClientMAC = net.HardwareAddr(b[6:12]).String()
	etherType := binary.BigEndian.Uint16(b[12:14])
	offset := 14

	if etherType == 0x8100 && len(b) >= offset+4 {
		// 802.1Q VLAN Tag
		tci := binary.BigEndian.Uint16(b[offset : offset+2])
		rec.LanVLAN = tci & 0x0FFF
		etherType = binary.BigEndian.Uint16(b[offset+2 : offset+4])
		offset += 4
	}

	if etherType == 0x0800 {
		dissectIPv4(b[offset:], rec)
	} else if etherType == 0x86DD {
		dissectIPv6(b[offset:], rec)
	}
}

func dissectIPv4(b []byte, rec *JSONFlowRecord) {
	if len(b) < 20 {
		return
	}

	rec.IPProtocolVersion = 4
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	rec.l3 = b

	rec.L4Proto = b[9]
	rec.TOS = b[1]
	rec.SrcTTL = b[8]
	rec.LanIP = net.IP(b[12:16]).String()
	rec.WanIP = net.IP(b[16:20]).String()
	rec.Direction = "upstream"

	payload := b[ihl:]
	dissectTransport(payload, rec.L4Proto, rec)
}

func dissectIPv6(b []byte, rec *JSONFlowRecord) {
	if len(b) < 40 {
		return
	}

	rec.IPProtocolVersion = 6
	rec.l3 = b
	rec.L4Proto = b[6]
	rec.SrcTTL = b[7] // Hop Limit
	rec.LanIP = net.IP(b[8:24]).String()
	rec.WanIP = net.IP(b[24:40]).String()
	rec.Direction = "upstream"

	payload := b[40:]
	dissectTransport(payload, rec.L4Proto, rec)
}

func dissectTransport(b []byte, proto uint8, rec *JSONFlowRecord) {
	switch proto {
	case 6:
		// TCP
		if len(b) >= 4 {
			rec.LanL4Port = binary.BigEndian.Uint16(b[0:2])
			rec.WanL4Port = binary.BigEndian.Uint16(b[2:4])
		}
		if len(b) >= 14 {
			rec.TCPFlags = FormatTCPFlags(b[13] & 0x3F)
		}
		if len(b) >= 20 {
			dataOffset := int((b[12] >> 4) * 4)
			if dataOffset >= 20 && dataOffset < len(b) {
				parseHTTPPayload(rec, b[dataOffset:])
			}
		}
	case 17:
		// UDP
		if len(b) >= 4 {
			rec.LanL4Port = binary.BigEndian.Uint16(b[0:2])
			rec.WanL4Port = binary.BigEndian.Uint16(b[2:4])
		}
	case 1:
		// ICMP
		if len(b) >= 2 {
			rec.LanL4Port = uint16(b[0]) // type
			rec.WanL4Port = uint16(b[1]) // code
		}
	}
}

func parseHTTPPayload(rec *JSONFlowRecord, payload []byte) {
	if len(payload) < 10 {
		return
	}
	if bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("HEAD ")) ||
		bytes.HasPrefix(payload, []byte("PUT ")) ||
		bytes.HasPrefix(payload, []byte("DELETE ")) {

		lines := bytes.Split(payload, []byte("\r\n"))
		for _, line := range lines {
			lower := bytes.ToLower(line)
			if bytes.HasPrefix(lower, []byte("user-agent: ")) {
				rec.HTTPUserAgent = string(bytes.TrimSpace(line[12:]))
			} else if bytes.HasPrefix(lower, []byte("host: ")) {
				host := string(bytes.TrimSpace(line[6:]))
				rec.HTTPHost = host
				if rec.Host == "" {
					rec.Host = host
				}
			}
		}
	}
}
