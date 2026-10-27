package flow

import (
	"encoding/json"
	"time"
)

// ParserConfig holds configuration options for flow parsing.
type ParserConfig struct {
	TemplateTTL         time.Duration
	RenormalizeSampling bool
	ExcludeFields       []string
	HomeNets            []string
	SpanPort            bool
	ApplicationsFile    string
	HostsPath           string
}

// JSONFlowRecord represents the canonical RedBorder flow record emitted to Kafka, matching f2k.
type JSONFlowRecord struct {
	Type                    string  `json:"type"`                                  // "netflowv10", "netflowv9", "netflowv5", "sflow"
	FlowSequence            string  `json:"flow_sequence,omitempty"`
	ObservationDomainID     *uint32 `json:"observation_domain_id,omitempty"`       // NetFlow v9 Source ID or IPFIX Observation Domain ID
	IPProtocolVersion       uint8   `json:"ip_protocol_version"`                    // 4 or 6
	L4Proto                 uint8   `json:"l4_proto"`                               // 6 = TCP, 17 = UDP, 1 = ICMP, etc.
	InputVRF                *uint32 `json:"input_vrf,omitempty"`
	OutputVRF               *uint32 `json:"output_vrf,omitempty"`
	FlowEndReason           string  `json:"flow_end_reason,omitempty"`             // "idle timeout", "active timeout", etc.
	BiflowDirection         string  `json:"biflow_direction,omitempty"`            // "initiator", "reverse initiator"
	ApplicationIDName       string  `json:"application_id_name,omitempty"`         // e.g. "3:123"
	ApplicationID           string  `json:"application_id,omitempty"`              // e.g. "3:123"
	EngineIDName            string  `json:"engine_id_name,omitempty"`              // e.g. "3"
	ApplicationName         string  `json:"application_name,omitempty"`
	Direction               string  `json:"direction,omitempty"`                   // "upstream", "downstream"
	IsOpenPort              bool    `json:"is_open_port,omitempty"`
	LanInterface            uint32  `json:"lan_interface,omitempty"`
	LanInterfaceName        string  `json:"lan_interface_name,omitempty"`
	LanInterfaceDescription string  `json:"lan_interface_description,omitempty"`
	WanInterface            uint32  `json:"wan_interface,omitempty"`
	WanInterfaceName        string  `json:"wan_interface_name,omitempty"`
	WanInterfaceDescription string  `json:"wan_interface_description,omitempty"`
	ClientMAC               string  `json:"client_mac,omitempty"`
	ServerMAC               string  `json:"server_mac,omitempty"`
	WanIP                   string  `json:"wan_ip,omitempty"`
	LanIP                   string  `json:"lan_ip,omitempty"`
	WanL4Port               uint16  `json:"wan_l4_port,omitempty"`
	LanL4Port               uint16  `json:"lan_l4_port,omitempty"`
	LanVLAN                 uint16  `json:"lan_vlan,omitempty"`
	TCPFlags                string  `json:"tcp_flags,omitempty"`
	TOS                     uint8   `json:"tos,omitempty"`
	SrcTTL                  uint8   `json:"src_ttl,omitempty"`
	DstTTL                  uint8   `json:"dst_ttl,omitempty"`
	Host                    string  `json:"host,omitempty"`                        // TLS SNI, HTTP Host, or DNS domain
	HTTPUserAgent           string  `json:"http_user_agent,omitempty"`
	HTTPURL                 string  `json:"http_url,omitempty"`
	HTTPHost                string  `json:"http_host,omitempty"`
	HTTPReferer             string  `json:"http_referer,omitempty"`
	Bytes                   uint64  `json:"bytes"`
	Pkts                    uint64  `json:"pkts"`
	SamplingRate            uint32  `json:"sampling_rate,omitempty"`
	Timestamp               int64   `json:"timestamp"`
	StartTime               int64   `json:"start_time,omitempty"`
	EndTime                 int64   `json:"end_time,omitempty"`
	Duration                int64   `json:"duration,omitempty"`                    // milliseconds
	SensorIP                string  `json:"sensor_ip,omitempty"`
	SensorUUID              string  `json:"sensor_uuid,omitempty"`
	SensorName              string  `json:"sensor_name,omitempty"`
}

// ToFilteredJSON marshals the flow record to JSON while stripping any fields specified in excludeFields.
func (r *JSONFlowRecord) ToFilteredJSON(excludeFields []string) ([]byte, error) {
	if len(excludeFields) == 0 {
		return json.Marshal(r)
	}

	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	for _, field := range excludeFields {
		delete(m, field)
	}

	return json.Marshal(m)
}
