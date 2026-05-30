package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestDnsCacheGetAndPut(t *testing.T) {
	c := NewDnsCache(3, 100) // max size: 3, TTL: 100ms

	questions := []ParsedQuestion{
		{Name: "test.local", Type: 1},
	}
	key := c.GenerateCacheKey(questions)

	// Mock valid response (12 bytes minimal header)
	response := make([]byte, 12)
	binary.BigEndian.PutUint16(response[4:6], 1) // QDCOUNT = 1

	c.Put(key, response)

	// Immediate Get should succeed
	retrieved, _, ok := c.Get(key)
	if !ok {
		t.Fatal("expected key to exist in cache, got not found")
	}

	if !bytes.Equal(retrieved[:12], response[:12]) {
		t.Error("cached response header mismatch")
	}

	// Sleep to exceed TTL
	time.Sleep(120 * time.Millisecond)

	_, _, okAfterSleep := c.Get(key)
	if okAfterSleep {
		t.Error("expected key to be expired and evicted from cache after sleeping")
	}
}

func TestDnsCacheEviction(t *testing.T) {
	c := NewDnsCache(2, 5000) // max size: 2

	k1 := c.GenerateCacheKey([]ParsedQuestion{{Name: "q1.local", Type: 1}})
	k2 := c.GenerateCacheKey([]ParsedQuestion{{Name: "q2.local", Type: 1}})
	k3 := c.GenerateCacheKey([]ParsedQuestion{{Name: "q3.local", Type: 1}})

	r := make([]byte, 12)

	c.Put(k1, r)
	c.Put(k2, r)

	// Touch k1 to move it to most recently used
	_, _, _ = c.Get(k1)

	// Put k3, which should trigger eviction of the oldest (k2)
	c.Put(k3, r)

	_, _, foundK2 := c.Get(k2)
	if foundK2 {
		t.Error("expected k2 to be evicted from cache, but it was found")
	}

	_, _, foundK1 := c.Get(k1)
	if !foundK1 {
		t.Error("expected k1 to be retained in cache after being accessed, but it was evicted")
	}
}
