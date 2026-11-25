package flow

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// testPEN is an arbitrary enterprise number; the enterprise IEs are decoded for any PEN.
const testPEN = 12345

type ipfixTestField struct {
	id    uint16
	pen   uint32 // non-zero sets the enterprise bit
	value []byte
}

// buildIPFIX returns one IPFIX message with a template (ID 260) and a single data record.
func buildIPFIX(fields []ipfixTestField) []byte {
	w := func(b *bytes.Buffer, v ...any) {
		for _, x := range v {
			_ = binary.Write(b, binary.BigEndian, x)
		}
	}

	tmpl := new(bytes.Buffer)
	for _, f := range fields {
		if f.pen != 0 {
			w(tmpl, f.id|0x8000, uint16(len(f.value)), f.pen)
		} else {
			w(tmpl, f.id, uint16(len(f.value)))
		}
	}
	rec := new(bytes.Buffer)
	for _, f := range fields {
		rec.Write(f.value)
	}

	body := new(bytes.Buffer)
	w(body, uint16(2), uint16(8+tmpl.Len()), uint16(260), uint16(len(fields)))
	body.Write(tmpl.Bytes())
	w(body, uint16(260), uint16(4+rec.Len()))
	body.Write(rec.Bytes())

	msg := new(bytes.Buffer)
	w(msg, uint16(10), uint16(16+body.Len()), uint32(1700000000), uint32(0), uint32(0))
	msg.Write(body.Bytes())
	return msg.Bytes()
}

// padded returns s in a fixed-length field filled with NUL bytes.
func padded(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

func TestNULPaddedStringFields(t *testing.T) {
	addrs := []ipfixTestField{
		{id: IE_SOURCE_IPV4_ADDRESS, value: []byte{10, 0, 0, 1}},
		{id: IE_DESTINATION_IPV4_ADDRESS, value: []byte{1, 1, 1, 1}},
	}

	tests := []struct {
		name                      string
		fields                    []ipfixTestField
		host, appName, sensorName string
	}{
		{
			name: "standard IEs",
			fields: []ipfixTestField{
				{id: IE_HTTP_HOST_NAME_V9, value: padded("www.example.com", 32)},
				{id: IE_APPLICATION_NAME, value: padded("TLS", 16)},
				{id: IE_REDBORDER_SENSOR_NAME, value: padded("sensor1", 16)},
			},
			host: "www.example.com", appName: "TLS", sensorName: "sensor1",
		},
		{
			name: "enterprise IEs",
			fields: []ipfixTestField{
				{id: IE_REDBORDER_WEBSITE_URL, pen: testPEN, value: padded("www.example.com", 32)},
				{id: IE_REDBORDER_APP_PROTOCOL, pen: testPEN, value: padded("TLS", 16)},
				{id: IE_REDBORDER_SENSOR_NAME, pen: testPEN, value: padded("sensor1", 16)},
			},
			host: "www.example.com", appName: "TLS", sensorName: "sensor1",
		},
		{
			name: "unpadded",
			fields: []ipfixTestField{
				{id: IE_HTTP_HOST_NAME_V9, value: []byte("www.example.com")},
				{id: IE_APPLICATION_NAME, value: []byte("TLS")},
			},
			host: "www.example.com", appName: "TLS",
		},
		{
			name: "only NULs",
			fields: []ipfixTestField{
				{id: IE_HTTP_HOST_NAME_V9, value: make([]byte, 32)},
				{id: IE_APPLICATION_NAME, value: make([]byte, 16)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewFlowParser(&ParserConfig{})
			recs, err := p.Parse(buildIPFIX(append(addrs, tt.fields...)), "192.0.2.10")
			if err != nil || len(recs) != 1 {
				t.Fatalf("Parse: err=%v records=%d", err, len(recs))
			}
			r := recs[0]
			if r.Host != tt.host || r.ApplicationName != tt.appName || r.SensorName != tt.sensorName {
				t.Errorf("host=%q application_name=%q sensor_name=%q, want %q %q %q",
					r.Host, r.ApplicationName, r.SensorName, tt.host, tt.appName, tt.sensorName)
			}
		})
	}
}
