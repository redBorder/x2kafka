package flow

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	defaultAppCacheTTL = 10 * time.Minute
	appCacheMaxEntries = 65536
	// Ports from here on are treated as ephemeral (client side) and are never cached.
	ephemeralPortStart = 32768
)

type serverKey struct {
	ip    string
	port  uint16
	proto uint8
}

type serverApp struct {
	name    string
	id      uint16
	expires time.Time
}

// serverAppCache remembers payload-based detections per server endpoint. sFlow samples
// are mostly mid-flow packets nDPI cannot identify by themselves, so later samples
// towards the same server inherit the detection. Not safe for concurrent use.
type serverAppCache struct {
	ttl     time.Duration
	entries map[serverKey]serverApp
}

func newServerAppCache(ttl time.Duration) *serverAppCache {
	if ttl <= 0 {
		ttl = defaultAppCacheTTL
	}
	return &serverAppCache{ttl: ttl, entries: make(map[serverKey]serverApp)}
}

func (c *serverAppCache) get(k serverKey, now time.Time) (serverApp, bool) {
	e, ok := c.entries[k]
	if !ok {
		return serverApp{}, false
	}
	if now.After(e.expires) {
		delete(c.entries, k)
		return serverApp{}, false
	}
	return e, true
}

func (c *serverAppCache) put(k serverKey, name string, id uint16, now time.Time) {
	if _, exists := c.entries[k]; !exists && len(c.entries) >= appCacheMaxEntries {
		for key, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, key)
			}
		}
		if len(c.entries) >= appCacheMaxEntries {
			return
		}
	}
	c.entries[k] = serverApp{name: name, id: id, expires: now.Add(c.ttl)}
}

// serverEndpoint picks the side of a sampled packet most likely to be the server:
// the one with the lower port. Must be called before the home_nets orientation,
// while lan_* is still the packet source and wan_* the destination.
func serverEndpoint(rec *JSONFlowRecord) (serverKey, bool) {
	if rec.L4Proto != 6 && rec.L4Proto != 17 {
		return serverKey{}, false
	}
	ip, port := rec.WanIP, rec.WanL4Port
	if rec.LanL4Port < rec.WanL4Port {
		ip, port = rec.LanIP, rec.LanL4Port
	}
	if ip == "" || port == 0 || port >= ephemeralPortStart {
		return serverKey{}, false
	}
	return serverKey{ip: ip, port: port, proto: rec.L4Proto}, true
}

func setApp(rec *JSONFlowRecord, engine int, id uint32, name string) {
	rec.EngineIDName = fmt.Sprintf("%d", engine)
	rec.ApplicationID = fmt.Sprintf("%d:%d", engine, id)
	rec.ApplicationIDName = name
	rec.ApplicationName = name
}

// classifySFlow fills the application fields of an sFlow record, in this order:
// nDPI payload detection, a previous detection for the same server, nDPI's guess by
// IP or port, and finally the port mapping from the applications dictionary.
func (p *FlowParser) classifySFlow(rec *JSONFlowRecord) {
	now := time.Now()
	server, hasServer := serverEndpoint(rec)

	if p.ndpi != nil && len(rec.l3) > 0 {
		m := p.ndpi.Classify(fitL3Length(rec.l3), now.UnixMilli())
		if m.Confidence == AppByDPI {
			if hasServer {
				p.appCache.put(server, m.Name, m.ID, now)
			}
			setApp(rec, appEngineNDPI, uint32(m.ID), strings.ToLower(m.Name))
			return
		}
		if hasServer {
			if cached, ok := p.appCache.get(server, now); ok {
				setApp(rec, appEngineNDPI, uint32(cached.id), strings.ToLower(cached.name))
				return
			}
		}
		if m.Confidence != AppUnknown {
			setApp(rec, appEngineNDPI, uint32(m.ID), strings.ToLower(m.Name))
			return
		}
	}

	if p.cache == nil || (rec.L4Proto != 6 && rec.L4Proto != 17) {
		return
	}
	ports := [2]uint16{rec.LanL4Port, rec.WanL4Port}
	if ports[1] < ports[0] {
		ports[0], ports[1] = ports[1], ports[0]
	}
	for _, port := range ports {
		if port == 0 {
			continue
		}
		if name, ok := p.cache.LookupDictionary(uint64(appEngineL4Port)<<24 | uint64(port)); ok {
			setApp(rec, appEngineL4Port, uint32(port), name)
			return
		}
	}
}

// fitL3Length returns the packet with its IP (and UDP) length fields lowered to the
// captured size. sFlow headers are truncated, and nDPI discards UDP packets whose IP
// total length is larger than the bytes it was given. The input is never modified.
func fitL3Length(b []byte) []byte {
	if len(b) > 0xFFFF {
		b = b[:0xFFFF]
	}
	if len(b) < 20 {
		return b
	}

	var l4Off int
	var l4Proto uint8
	var lenOff int
	var lenVal uint16

	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0F) * 4
		if ihl < 20 || len(b) < ihl || int(binary.BigEndian.Uint16(b[2:4])) <= len(b) {
			return b
		}
		l4Off, l4Proto = ihl, b[9]
		lenOff, lenVal = 2, uint16(len(b))
	case 6:
		if len(b) < 40 || 40+int(binary.BigEndian.Uint16(b[4:6])) <= len(b) {
			return b
		}
		l4Off, l4Proto = 40, b[6]
		lenOff, lenVal = 4, uint16(len(b)-40)
	default:
		return b
	}

	out := make([]byte, len(b))
	copy(out, b)
	binary.BigEndian.PutUint16(out[lenOff:lenOff+2], lenVal)
	if l4Proto == 17 && len(out) >= l4Off+8 {
		binary.BigEndian.PutUint16(out[l4Off+4:l4Off+6], uint16(len(out)-l4Off))
	}
	return out
}
