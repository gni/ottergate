package audit

import (
	"testing"
	"time"
)

func TestLogBufferAddAndGet(t *testing.T) {
	b := &LogBuffer{
		events: make([]LogEvent, 0, 3),
		max:    3,
	}

	e1 := LogEvent{Timestamp: time.Now(), Type: "system", Details: "init 1"}
	e2 := LogEvent{Timestamp: time.Now(), Type: "system", Details: "init 2"}
	e3 := LogEvent{Timestamp: time.Now(), Type: "system", Details: "init 3"}
	e4 := LogEvent{Timestamp: time.Now(), Type: "system", Details: "init 4"}

	// 1. Initial empty checks
	if len(b.GetEvents()) != 0 {
		t.Error("expected empty log buffer on initialization")
	}

	// 2. Add elements under capacity
	b.Add(e1)
	b.Add(e2)

	events := b.GetEvents()
	if len(events) != 2 {
		t.Fatalf("expected 2 elements in buffer, got %d", len(events))
	}

	// Verify reverse-chronological order (newest first)
	if events[0].Details != "init 2" || events[1].Details != "init 1" {
		t.Error("expected reverse-chronological order in GetEvents")
	}

	// 3. Add to exceed capacity (should evict e1)
	b.Add(e3)
	b.Add(e4)

	eventsAfterCap := b.GetEvents()
	if len(eventsAfterCap) != 3 {
		t.Fatalf("expected buffer size capped at 3, got %d", len(eventsAfterCap))
	}

	// Verify oldest (e1) was evicted, and order is newest-first (e4, e3, e2)
	if eventsAfterCap[0].Details != "init 4" || eventsAfterCap[1].Details != "init 3" || eventsAfterCap[2].Details != "init 2" {
		t.Errorf("unexpected elements order after capacity eviction: %v", eventsAfterCap)
	}
}
