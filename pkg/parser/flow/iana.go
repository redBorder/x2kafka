package flow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Standard IANA Information Element IDs (RFC 7012 / RFC 3954)
const (
	IE_OCTET_DELTA_COUNT          = 1
	IE_PACKET_DELTA_COUNT         = 2
	IE_PROTOCOL_IDENTIFIER        = 4
	IE_IP_CLASS_OF_SERVICE        = 5
	IE_TCP_CONTROL_BITS           = 6
	IE_SOURCE_TRANSPORT_PORT      = 7
	IE_SOURCE_IPV4_ADDRESS        = 8
	IE_SOURCE_IPV4_PREFIX_LENGTH  = 9
	IE_INGRESS_INTERFACE          = 10
	IE_DESTINATION_TRANSPORT_PORT = 11
	IE_DESTINATION_IPV4_ADDRESS   = 12
	IE_DEST_IPV4_PREFIX_LENGTH    = 13
	IE_EGRESS_INTERFACE           = 14
	IE_IP_NEXT_HOP_IPV4_ADDRESS   = 15
	IE_BGP_SOURCE_AS_NUMBER       = 16
	IE_BGP_DEST_AS_NUMBER         = 17
	IE_FLOW_END_SYS_UPTIME        = 21 // LAST_SWITCHED in v9
	IE_FLOW_START_SYS_UPTIME      = 22 // FIRST_SWITCHED in v9
	IE_SOURCE_IPV6_ADDRESS        = 27
	IE_DESTINATION_IPV6_ADDRESS   = 28
	IE_ICMP_TYPE_CODE_IPV4        = 32
	IE_MIN_TTL                    = 52
	IE_MAX_TTL                    = 53
	IE_SOURCE_MAC_ADDRESS         = 56
	IE_POST_DESTINATION_MAC       = 57 // Post-destination MAC address (after routing)
	IE_VLAN_ID                    = 58
	IE_POST_VLAN_ID               = 59
	IE_IP_VERSION                 = 60
	IE_FLOW_DIRECTION             = 61
	IE_DESTINATION_MAC_ADDRESS    = 80
	IE_POST_SOURCE_MAC            = 81 // Post-source MAC address
	IE_IF_NAME                    = 82
	IE_IF_DESCRIPTION             = 83
	IE_HTTP_HOST_NAME_V9          = 87
	IE_APPLICATION_ID             = 95
	IE_APPLICATION_NAME           = 96
	IE_FLOW_END_REASON            = 136
	IE_FLOW_START_SECONDS         = 150
	IE_FLOW_END_SECONDS           = 151
	IE_TCP_CONTROL_BITS_IPFIX     = 183
	IE_MINIMUM_TTL_IPFIX          = 192
	IE_MAXIMUM_TTL_IPFIX          = 193
	IE_INGRESS_VRF_ID             = 234
	IE_EGRESS_VRF_ID              = 235
	IE_BIFLOW_DIRECTION           = 239
	IE_DOT1Q_VLAN_ID              = 243
	IE_POST_DOT1Q_VLAN_ID         = 254
	IE_HTTP_HOST_NAME_IPFIX       = 456

	// RedBorder Custom / Enterprise Fields
	IE_REDBORDER_IS_OPEN_PORT     = 301
	IE_REDBORDER_TCP_RTT          = 302
	IE_REDBORDER_WEBSITE_URL      = 303
	IE_REDBORDER_APP_PROTOCOL     = 304
	IE_REDBORDER_SENSOR_NAME      = 305
)

func decodeUint(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	default:
		var val uint64
		for _, byteVal := range b {
			val = (val << 8) | uint64(byteVal)
		}
		return val
	}
}

func decodeIP(b []byte) string {
	if len(b) == 4 || len(b) == 16 {
		ip := net.IP(b)
		return ip.String()
	}
	return ""
}

func decodeMAC(b []byte) string {
	if len(b) == 6 {
		return net.HardwareAddr(b).String()
	}
	return ""
}

// FormatTCPFlags formats a TCP flags byte into pipe-delimited string matching redborder-flow-agent.
func FormatTCPFlags(f uint8) string {
	if f == 0 {
		return ""
	}
	var flags []string
	if f&0x02 != 0 {
		flags = append(flags, "SYN")
	}
	if f&0x10 != 0 {
		flags = append(flags, "ACK")
	}
	if f&0x01 != 0 {
		flags = append(flags, "FIN")
	}
	if f&0x04 != 0 {
		flags = append(flags, "RST")
	}
	if f&0x08 != 0 {
		flags = append(flags, "PSH")
	}
	if f&0x20 != 0 {
		flags = append(flags, "URG")
	}
	if f&0x40 != 0 {
		flags = append(flags, "ECE")
	}
	if f&0x80 != 0 {
		flags = append(flags, "CWR")
	}
	return strings.Join(flags, "|")
}

func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func decodeAppID(val []byte) (string, string) {
	switch len(val) {
	case 4:
		engineID := fmt.Sprintf("%d", val[0])
		appID := uint32(val[1])<<16 | uint32(val[2])<<8 | uint32(val[3])
		return engineID, fmt.Sprintf("%s:%d", engineID, appID)
	case 8:
		pen := binary.BigEndian.Uint32(val[0:4])
		appID := binary.BigEndian.Uint32(val[4:8])
		if pen != 0 {
			engineID := fmt.Sprintf("%d", pen)
			return engineID, fmt.Sprintf("%s:%d", engineID, appID)
		}
		return "", fmt.Sprintf("%d", appID)
	case 6:
		pen := uint32(binary.BigEndian.Uint16(val[0:2]))
		appID := binary.BigEndian.Uint32(val[2:6])
		if pen != 0 {
			engineID := fmt.Sprintf("%d", pen)
			return engineID, fmt.Sprintf("%s:%d", engineID, appID)
		}
		return "", fmt.Sprintf("%d", appID)
	default:
		return "", fmt.Sprintf("%d", decodeUint(val))
	}
}

func applyFieldToRecord(rec *JSONFlowRecord, spec FieldSpec, val []byte, spanPort bool, cache *TemplateCache) {
	if spec.EnterpriseNumber == 0 {
		switch spec.TypeID {
		case IE_SOURCE_IPV4_ADDRESS, IE_SOURCE_IPV6_ADDRESS:
			rec.LanIP = decodeIP(val)
			if spec.TypeID == IE_SOURCE_IPV6_ADDRESS {
				rec.IPProtocolVersion = 6
			}
		case IE_DESTINATION_IPV4_ADDRESS, IE_DESTINATION_IPV6_ADDRESS:
			rec.WanIP = decodeIP(val)
			if spec.TypeID == IE_DESTINATION_IPV6_ADDRESS {
				rec.IPProtocolVersion = 6
			}
		case IE_SOURCE_TRANSPORT_PORT:
			rec.LanL4Port = uint16(decodeUint(val))
		case IE_DESTINATION_TRANSPORT_PORT:
			rec.WanL4Port = uint16(decodeUint(val))
		case IE_IP_CLASS_OF_SERVICE:
			rec.TOS = uint8(decodeUint(val))
		case IE_INGRESS_INTERFACE:
			rec.LanInterface = uint32(decodeUint(val))
			rec.LanInterfaceName = fmt.Sprintf("%d", rec.LanInterface)
			if cache != nil {
				domainID := uint32(0)
				if rec.ObservationDomainID != nil {
					domainID = *rec.ObservationDomainID
				}
				if ifName, ok := cache.GetIfName(rec.SensorIP, domainID, rec.LanInterface); ok && ifName != "" {
					rec.LanInterfaceName = ifName
				}
			}
			rec.LanInterfaceDescription = rec.LanInterfaceName
		case IE_EGRESS_INTERFACE:
			rec.WanInterface = uint32(decodeUint(val))
			rec.WanInterfaceName = fmt.Sprintf("%d", rec.WanInterface)
			if cache != nil {
				domainID := uint32(0)
				if rec.ObservationDomainID != nil {
					domainID = *rec.ObservationDomainID
				}
				if ifName, ok := cache.GetIfName(rec.SensorIP, domainID, rec.WanInterface); ok && ifName != "" {
					rec.WanInterfaceName = ifName
				}
			}
			rec.WanInterfaceDescription = rec.WanInterfaceName
		case IE_FLOW_DIRECTION:
			d := decodeUint(val)
			if d == 0 {
				rec.Direction = "upstream"
			} else if d == 1 {
				rec.Direction = "downstream"
			}
		case IE_FLOW_END_REASON:
			reason := decodeUint(val)
			switch reason {
			case 1:
				rec.FlowEndReason = "idle timeout"
			case 2:
				rec.FlowEndReason = "active timeout"
			case 3:
				rec.FlowEndReason = "end of flow"
			case 4:
				rec.FlowEndReason = "forced end"
			case 5:
				rec.FlowEndReason = "lack of resources"
			}
		case IE_INGRESS_VRF_ID:
			v := uint32(decodeUint(val))
			rec.InputVRF = &v
		case IE_EGRESS_VRF_ID:
			v := uint32(decodeUint(val))
			rec.OutputVRF = &v
		case IE_BIFLOW_DIRECTION:
			bdir := decodeUint(val)
			if bdir == 1 {
				rec.BiflowDirection = "initiator"
			} else if bdir == 2 {
				rec.BiflowDirection = "reverse initiator"
			}
		case IE_PROTOCOL_IDENTIFIER:
			rec.L4Proto = uint8(decodeUint(val))
		case IE_IP_VERSION:
			if rec.IPProtocolVersion == 0 {
				rec.IPProtocolVersion = uint8(decodeUint(val))
			}
		case IE_TCP_CONTROL_BITS, IE_TCP_CONTROL_BITS_IPFIX:
			rec.TCPFlags = FormatTCPFlags(uint8(decodeUint(val)))
		case IE_MIN_TTL, IE_MINIMUM_TTL_IPFIX:
			rec.SrcTTL = uint8(decodeUint(val))
		case IE_MAX_TTL, IE_MAXIMUM_TTL_IPFIX:
			rec.DstTTL = uint8(decodeUint(val))
		case IE_OCTET_DELTA_COUNT:
			rec.Bytes = decodeUint(val)
		case IE_PACKET_DELTA_COUNT:
			rec.Pkts = decodeUint(val)
		case IE_SOURCE_MAC_ADDRESS:
			rec.ClientMAC = decodeMAC(val)
		case IE_DESTINATION_MAC_ADDRESS:
			// On SPAN ports or if ServerMAC not set, use destination MAC
			if rec.ServerMAC == "" || spanPort {
				rec.ServerMAC = decodeMAC(val)
			}
		case IE_POST_DESTINATION_MAC:
			// Post-destination MAC (after routing): used unless on SPAN port mirror
			if !spanPort {
				rec.ServerMAC = decodeMAC(val)
			}
		case IE_POST_SOURCE_MAC:
			if !spanPort && rec.ClientMAC == "" {
				rec.ClientMAC = decodeMAC(val)
			}
		case IE_VLAN_ID, IE_DOT1Q_VLAN_ID:
			rec.LanVLAN = uint16(decodeUint(val))
		case IE_HTTP_HOST_NAME_V9, IE_HTTP_HOST_NAME_IPFIX, IE_REDBORDER_WEBSITE_URL:
			if isPrintableASCII(val) {
				rec.Host = string(val)
			}
		case IE_APPLICATION_ID:
			eng, app := decodeAppID(val)
			if eng != "" {
				rec.EngineIDName = eng
			}
			rec.ApplicationIDName = app
			rec.ApplicationID = app
			rec.ApplicationName = app

			// Check if we have a learned application name in cache or dictionary
			if cache != nil {
				domainID := uint32(0)
				if rec.ObservationDomainID != nil {
					domainID = *rec.ObservationDomainID
				}
				rawID := decodeUint(val)
				if name, ok := cache.GetAppName(rec.SensorIP, domainID, rawID); ok && name != "" {
					rec.ApplicationName = name
					rec.ApplicationIDName = name
				} else if len(val) == 8 {
					appID32 := uint64(binary.BigEndian.Uint32(val[4:8]))
					if name, ok := cache.GetAppName(rec.SensorIP, domainID, appID32); ok && name != "" {
						rec.ApplicationName = name
						rec.ApplicationIDName = name
					}
				} else if len(val) == 4 {
					appID24 := uint64(uint32(val[1])<<16 | uint32(val[2])<<8 | uint32(val[3]))
					if name, ok := cache.GetAppName(rec.SensorIP, domainID, appID24); ok && name != "" {
						rec.ApplicationName = name
						rec.ApplicationIDName = name
					}
				}
			}
		case IE_APPLICATION_NAME, IE_REDBORDER_APP_PROTOCOL:
			if isPrintableASCII(val) {
				rec.ApplicationName = strings.TrimRight(string(val), "\x00")
			} else if len(val) == 4 {
				eng, app := decodeAppID(val)
				if eng != "" {
					rec.EngineIDName = eng
				}
				rec.ApplicationIDName = app
				rec.ApplicationID = app
				rec.ApplicationName = app
			}
		case IE_REDBORDER_IS_OPEN_PORT:
			rec.IsOpenPort = decodeUint(val) != 0
		case IE_FLOW_START_SECONDS:
			rec.StartTime = int64(decodeUint(val))
		case IE_FLOW_END_SECONDS:
			rec.EndTime = int64(decodeUint(val))
			if rec.StartTime > 0 && rec.EndTime >= rec.StartTime {
				rec.Duration = (rec.EndTime - rec.StartTime) * 1000
			}
		case IE_REDBORDER_SENSOR_NAME:
			if isPrintableASCII(val) {
				rec.SensorName = string(val)
			}
		}
	} else {
		// Enterprise-specific Information Element
		if spec.EnterpriseNumber == 9 && spec.TypeID == 12235 {
			// Cisco AVC / NBAR2 HTTP sub-attributes
			if len(val) > 6 {
				tag := val[:6]
				content := strings.TrimRight(string(val[6:]), "\x00")
				if isPrintableASCII([]byte(content)) {
					switch {
					case bytes.Equal(tag, []byte{0x03, 0x00, 0x00, 0x50, 0x34, 0x03}):
						rec.HTTPUserAgent = content
					case bytes.Equal(tag, []byte{0x03, 0x00, 0x00, 0x50, 0x34, 0x02}):
						rec.HTTPHost = content
						if rec.Host == "" {
							rec.Host = content
						}
					case bytes.Equal(tag, []byte{0x03, 0x00, 0x00, 0x50, 0x34, 0x01}):
						rec.HTTPURL = content
					case bytes.Equal(tag, []byte{0x03, 0x00, 0x00, 0x50, 0x34, 0x04}):
						rec.HTTPReferer = content
					case bytes.Equal(tag, []byte{0x0d, 0x00, 0x01, 0xc5, 0x34, 0x01}):
						if rec.Host == "" {
							rec.Host = content
						}
					}
				}
			}
			return
		}

		switch spec.TypeID {
		case IE_REDBORDER_SENSOR_NAME:
			if isPrintableASCII(val) {
				rec.SensorName = string(val)
			}
		case IE_REDBORDER_WEBSITE_URL:
			if isPrintableASCII(val) {
				rec.Host = string(val)
			}
		case IE_REDBORDER_APP_PROTOCOL:
			if isPrintableASCII(val) {
				rec.ApplicationName = string(val)
			}
		}
	}
}
