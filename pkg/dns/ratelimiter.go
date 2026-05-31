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
	mu            sync.RWMutex
	buckets       map[string]*IpBucket
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
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, ok := rl.buckets[ip]

	if !ok || now.After(bucket.ResetTime) {
		if len(rl.buckets) >= rl.maxTrackedIps {
			rl.evictExpiredOrOldest(now)
		}

		rl.buckets[ip] = &IpBucket{
			Count:     1,
			ResetTime: now.Add(rl.window),
		}
		return true
	}

	if bucket.Count >= rl.maxRequests {
		return false
	}

	bucket.Count++
	return true
}

func (rl *RateLimiter) evictExpiredOrOldest(now time.Time) {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, bucket := range rl.buckets {
		if now.After(bucket.ResetTime) {
			delete(rl.buckets, k)
			return
		}
		if first || bucket.ResetTime.Before(oldestTime) {
			oldestTime = bucket.ResetTime
			oldestKey = k
			first = false
		}
	}

	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
	}
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
	for ip, bucket := range rl.buckets {
		if now.After(bucket.ResetTime) {
			delete(rl.buckets, ip)
		}
	}
}