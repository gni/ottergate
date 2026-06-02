package audit

import (
	"sync"
	"time"
)

type LogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`       // "dns", "http", "firewall", "command", "system", "error"
	ClientIP  string    `json:"client_ip"`
	Details   string    `json:"details"`
	Status    string    `json:"status"`     // "allow", "deny", "info", "error"
	Target    string    `json:"target"`
}

type LogBuffer struct {
	mu     sync.RWMutex
	events []LogEvent
	max    int
}

var GlobalBuffer = &LogBuffer{
	events: make([]LogEvent, 0, 1000),
	max:    1000,
}

func (b *LogBuffer) Add(e LogEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) >= b.max {
		// Evict oldest
		b.events = b.events[1:]
	}
	b.events = append(b.events, e)
}

func (b *LogBuffer) GetEvents() []LogEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Return a copy in reverse order (newest first for standard dashboards)
	length := len(b.events)
	res := make([]LogEvent, length)
	for i := 0; i < length; i++ {
		res[i] = b.events[length-1-i]
	}
	return res
}