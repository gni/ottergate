package dns

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type CacheEntry struct {
	Response   []byte
	InsertedAt time.Time
	TtlMs      int
}

type DnsCache struct {
	mu         sync.Mutex
	cacheMap   map[string]*CacheEntry
	keyList    []string // simple slice to keep track of insertion order for eviction
	maxSize    int
	defaultTtl int // in milliseconds
}

func NewDnsCache(maxSize int, defaultTtlMs int) *DnsCache {
	if maxSize <= 0 {
		maxSize = 1024
	}
	return &DnsCache{
		cacheMap:   make(map[string]*CacheEntry),
		maxSize:    maxSize,
		defaultTtl: defaultTtlMs,
	}
}

func (c *DnsCache) GenerateCacheKey(questions []ParsedQuestion) string {
	var rawParts []string
	for _, q := range questions {
		rawParts = append(rawParts, fmt.Sprintf("%s:%d", hex.EncodeToString([]byte(q.Name)), q.Type))
	}
	raw := strings.Join(rawParts, "|")
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func (c *DnsCache) Get(key string) ([]byte, int, bool) {
	if c.defaultTtl <= 0 {
		return nil, 0, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cacheMap[key]
	if !ok {
		return nil, 0, false
	}

	elapsed := int(time.Since(entry.InsertedAt).Milliseconds())
	if elapsed >= c.defaultTtl {
		c.deleteKey(key)
		return nil, 0, false
	}

	// Move to back (most recently used)
	c.touchKey(key)

	remainingTtlMs := c.defaultTtl - elapsed
	remainingSeconds := remainingTtlMs / 1000
	if remainingSeconds <= 0 {
		remainingSeconds = 1
	}

	// Rewrite response TTL
	rewritten := c.rewriteResponseTtl(entry.Response, uint32(remainingSeconds))
	return rewritten, remainingTtlMs, true
}

func (c *DnsCache) Put(key string, response []byte) {
	if c.defaultTtl <= 0 || len(response) < 12 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If key already exists, update it
	if _, ok := c.cacheMap[key]; ok {
		c.cacheMap[key] = &CacheEntry{
			Response:   response,
			InsertedAt: time.Now(),
			TtlMs:      c.defaultTtl,
		}
		c.touchKey(key)
		return
	}

	// Check max size eviction
	for len(c.cacheMap) >= c.maxSize {
		c.evictOldest()
	}

	remainingSeconds := c.defaultTtl / 1000
	if remainingSeconds <= 0 {
		remainingSeconds = 1
	}
	modified := c.rewriteResponseTtl(response, uint32(remainingSeconds))

	c.cacheMap[key] = &CacheEntry{
		Response:   modified,
		InsertedAt: time.Now(),
		TtlMs:      c.defaultTtl,
	}
	c.keyList = append(c.keyList, key)
}

func (c *DnsCache) touchKey(key string) {
	for i, k := range c.keyList {
		if k == key {
			c.keyList = append(c.keyList[:i], c.keyList[i+1:]...)
			break
		}
	}
	c.keyList = append(c.keyList, key)
}

func (c *DnsCache) deleteKey(key string) {
	delete(c.cacheMap, key)
	for i, k := range c.keyList {
		if k == key {
			c.keyList = append(c.keyList[:i], c.keyList[i+1:]...)
			break
		}
	}
}

func (c *DnsCache) evictOldest() {
	if len(c.keyList) == 0 {
		return
	}
	oldest := c.keyList[0]
	c.deleteKey(oldest)
}

func (c *DnsCache) skipQuestionSection(buffer []byte, offset int) int {
	saved := offset
	for offset < len(buffer) {
		length := buffer[offset]
		if length == 0 {
			offset++
			break
		}
		if (length & 0xc0) == 0xc0 {
			if offset+1 >= len(buffer) {
				return saved
			}
			offset += 2
			break
		}
		if offset+1+int(length) > len(buffer) {
			return saved
		}
		offset += 1 + int(length)
	}
	if offset+4 > len(buffer) {
		return saved
	}
	return offset + 4
}

func (c *DnsCache) rewriteResponseTtl(response []byte, newTtl uint32) []byte {
	if len(response) < 12 {
		return response
	}

	result := make([]byte, len(response))
	copy(result, response)

	qdcount := binary.BigEndian.Uint16(response[4:6])
	offset := 12

	for i := 0; i < int(qdcount); i++ {
		nextOffset := c.skipQuestionSection(response, offset)
		if nextOffset == offset {
			break
		}
		offset = nextOffset
	}

	ancount := binary.BigEndian.Uint16(response[6:8])
	for i := 0; i < int(ancount) && offset < len(response); i++ {
		// Safely skip the domain name, Type, and Class using skipQuestionSection
		ttlOffset := c.skipQuestionSection(response, offset)
		if ttlOffset == offset || ttlOffset+4 > len(response) {
			break
		}

		binary.BigEndian.PutUint32(result[ttlOffset:], newTtl)

		rdLengthOffset := ttlOffset + 4
		if rdLengthOffset+2 > len(response) {
			break
		}
		rdlength := binary.BigEndian.Uint16(response[rdLengthOffset:])
		offset = rdLengthOffset + 2 + int(rdlength) // skip TTL, rdlength and rdata
	}

	return result
}
