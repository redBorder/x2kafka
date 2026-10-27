package flow

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FieldSpec represents a field definition in a NetFlow v9 or IPFIX template.
type FieldSpec struct {
	TypeID           uint16
	Length           uint16
	EnterpriseNumber uint32 // Non-zero if enterprise bit was set (IPFIX)
}

// Template represents a registered template definition.
type Template struct {
	TemplateID       uint16
	Fields           []FieldSpec
	LastSeen         time.Time
	IsOptionTemplate bool
}

// TemplateCache is a thread-safe cache for flow templates, learned application names, and interface names.
type TemplateCache struct {
	mu            sync.RWMutex
	templates     map[string]Template // key: "exporterIP:domainID:templateID"
	appNames      map[string]string   // key: "exporterIP:domainID:appID"
	ifNames       map[string]string   // key: "exporterIP:domainID:ifIndex"
	appDictionary map[uint64]string   // global fallback dictionary from redBorder applications file
	ttl           time.Duration
}

// NewTemplateCache creates a new template cache with the given TTL.
func NewTemplateCache(ttl time.Duration) *TemplateCache {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &TemplateCache{
		templates:     make(map[string]Template),
		appNames:      make(map[string]string),
		ifNames:       make(map[string]string),
		appDictionary: make(map[uint64]string),
		ttl:           ttl,
	}
}

func cacheKey(exporterIP string, domainID uint32, templateID uint16) string {
	return fmt.Sprintf("%s:%d:%d", exporterIP, domainID, templateID)
}

// Get retrieves a template from the cache.
func (c *TemplateCache) Get(exporterIP string, domainID uint32, templateID uint16) (Template, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(exporterIP, domainID, templateID)
	tmpl, ok := c.templates[key]
	if !ok {
		return Template{}, false
	}
	if time.Since(tmpl.LastSeen) > c.ttl {
		return Template{}, false
	}
	return tmpl, true
}

// Set stores or updates a template in the cache.
func (c *TemplateCache) Set(exporterIP string, domainID uint32, templateID uint16, tmpl Template) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tmpl.LastSeen = time.Now()
	key := cacheKey(exporterIP, domainID, templateID)
	c.templates[key] = tmpl
}

// SetAppName stores a learned application name for a given exporter, domain, and application ID.
func (c *TemplateCache) SetAppName(exporterIP string, domainID uint32, appID uint64, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%s:%d:%d", exporterIP, domainID, appID)
	c.appNames[key] = name
}

// GetAppName retrieves an application name from the learned cache, falling back to the static dictionary.
func (c *TemplateCache) GetAppName(exporterIP string, domainID uint32, appID uint64) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s:%d:%d", exporterIP, domainID, appID)
	if name, ok := c.appNames[key]; ok && name != "" {
		return name, true
	}
	// Fallback to static dictionary
	if name, ok := c.appDictionary[appID]; ok && name != "" {
		return name, true
	}
	return "", false
}

// SetIfName stores a learned interface name for a given exporter, domain, and interface index.
func (c *TemplateCache) SetIfName(exporterIP string, domainID uint32, ifIndex uint32, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%s:%d:%d", exporterIP, domainID, ifIndex)
	c.ifNames[key] = name
}

// GetIfName retrieves an interface name for a given exporter, domain, and interface index.
func (c *TemplateCache) GetIfName(exporterIP string, domainID uint32, ifIndex uint32) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s:%d:%d", exporterIP, domainID, ifIndex)
	name, ok := c.ifNames[key]
	return name, ok
}

// LoadApplicationDictionary loads application names from a redBorder applications file (format: "<name> <id>").
func (c *TemplateCache) LoadApplicationDictionary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	c.mu.Lock()
	defer c.mu.Unlock()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			id, err := strconv.ParseUint(parts[1], 10, 64)
			if err == nil {
				c.appDictionary[id] = parts[0]
			}
		}
	}
	return scanner.Err()
}

// PruneStale removes templates that have not been seen within the TTL duration.
func (c *TemplateCache) PruneStale() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	now := time.Now()
	for k, tmpl := range c.templates {
		if now.Sub(tmpl.LastSeen) > c.ttl {
			delete(c.templates, k)
			count++
		}
	}
	return count
}
