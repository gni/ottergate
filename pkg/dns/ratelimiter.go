package dns

import (
	"sync"
	"time"
)

type IpBucket struct {
	Count     int
	ResetTime time.Time
}

type RateLimiter struct {
	mu            sync.Mutex
	buckets       map[string]*IpBucket
	keyList       []string // track key order for eviction
	maxRequests   int
	window        time.Duration
	maxTrackedIps int
	stopChan      chan struct{}
}

func NewRateLimiter(maxRequests int, windowMs int, maxTrackedIps int) *RateLimiter {
	if maxTrackedIps <= 0 {
		maxTrackedIps = 100000
	}
	rl := &RateLimiter{
		buckets:       make(map[string]*IpBucket),
		maxRequests:   maxRequests,
		window:        time.Duration(windowMs) * time.Millisecond,
		maxTrackedIps: maxTrackedIps,
		stopChan:      make(chan struct{}),
	}
	go rl.startGarbageCollector()
	return rl
}

func (rl *RateLimiter) Destroy() {
	close(rl.stopChan)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = nil
	rl.keyList = nil
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, ok := rl.buckets[ip]

	if !ok || now.After(bucket.ResetTime) {
		// Evict oldest if capacity exceeded
		for len(rl.buckets) >= rl.maxTrackedIps {
			rl.evictOldest()
		}

		bucket = &IpBucket{
			Count:     1,
			ResetTime: now.Add(rl.window),
		}
		rl.buckets[ip] = bucket
		rl.touchKey(ip)
		return true
	}

	if bucket.Count >= rl.maxRequests {
		return false
	}

	bucket.Count++
	return true
}

func (rl *RateLimiter) touchKey(key string) {
	for i, k := range rl.keyList {
		if k == key {
			rl.keyList = append(rl.keyList[:i], rl.keyList[i+1:]...)
			break
		}
	}
	rl.keyList = append(rl.keyList, key)
}

func (rl *RateLimiter) evictOldest() {
	if len(rl.keyList) == 0 {
		return
	}
	oldest := rl.keyList[0]
	delete(rl.buckets, oldest)
	rl.keyList = rl.keyList[1:]
}

func (rl *RateLimiter) startGarbageCollector() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.garbageCollect()
		case <-rl.stopChan:
			return
		}
	}
}

func (rl *RateLimiter) garbageCollect() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	expiredCount := 0
	for ip, bucket := range rl.buckets {
		if now.After(bucket.ResetTime) {
			delete(rl.buckets, ip)
			expiredCount++
		}
	}

	if expiredCount == 0 {
		return
	}

	// Single O(N) pass to filter out deleted keys from keyList
	newKeyList := make([]string, 0, len(rl.buckets))
	for _, ip := range rl.keyList {
		if _, exists := rl.buckets[ip]; exists {
			newKeyList = append(newKeyList, ip)
		}
	}
	rl.keyList = newKeyList
}
