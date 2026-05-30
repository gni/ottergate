package dns

import (
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(2, 50, 10) // 2 requests max per 50ms, max 10 IPs
	defer rl.Destroy()

	ip := "192.168.1.100"

	// 1. First request allowed
	if !rl.Allow(ip) {
		t.Error("expected first request to be allowed")
	}

	// 2. Second request allowed
	if !rl.Allow(ip) {
		t.Error("expected second request to be allowed")
	}

	// 3. Third request should be blocked
	if rl.Allow(ip) {
		t.Error("expected third request to be blocked due to rate limit threshold")
	}

	// 4. Sleep to let the window reset
	time.Sleep(70 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Error("expected request to be allowed after rate limit window reset")
	}
}

func TestRateLimiterEviction(t *testing.T) {
	rl := NewRateLimiter(1, 5000, 2) // max capacity: 2 IPs
	defer rl.Destroy()

	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")

	// Allow "3.3.3.3" which should evict "1.1.1.1"
	rl.Allow("3.3.3.3")

	rl.mu.Lock()
	_, ok1 := rl.buckets["1.1.1.1"]
	_, ok2 := rl.buckets["2.2.2.2"]
	_, ok3 := rl.buckets["3.3.3.3"]
	rl.mu.Unlock()

	if ok1 {
		t.Error("expected 1.1.1.1 to be evicted from rate limiter capacity bounds")
	}
	if !ok2 || !ok3 {
		t.Error("expected 2.2.2.2 and 3.3.3.3 to be retained in rate limiter")
	}
}
