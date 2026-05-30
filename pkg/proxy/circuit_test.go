package proxy

import (
	"errors"
	"testing"
	"time"
)

func TestProxyCircuitBreakerStates(t *testing.T) {
	cb := NewProxyCircuitBreaker("test.local")
	cb.threshold = 3
	cb.resetTimeout = 50 * time.Millisecond

	// 1. Initial state must be Closed (0 in standard iota)
	if cb.state != StateClosed {
		t.Errorf("expected initial state to be Closed (0), got %d", cb.state)
	}

	// 2. Trigger failures to transition to Open
	dummyActionFail := func() error {
		return errors.New("connection failed")
	}

	for i := 0; i < 3; i++ {
		_ = cb.Execute(dummyActionFail)
	}

	if cb.state != StateOpen {
		t.Errorf("expected state to transition to Open (1) after 3 failures, got %d", cb.state)
	}

	// Execution should immediately block and return offline error
	err := cb.Execute(func() error { return nil })
	if err == nil || err.Error() != "Target Offline (Circuit Breaker OPEN)" {
		t.Errorf("expected circuit breaker blocked execution error, got: %v", err)
	}

	// 3. Sleep to let circuit breaker transition to HalfOpen
	time.Sleep(60 * time.Millisecond)

	dummyActionSuccess := func() error {
		return nil
	}

	errSuccess := cb.Execute(dummyActionSuccess)
	if errSuccess != nil {
		t.Fatalf("unexpected error during half-open execution: %v", errSuccess)
	}

	if cb.state != StateClosed {
		t.Errorf("expected state to transition back to Closed (0) after successful execution, got %d", cb.state)
	}
}
