package proxy

import (
	"errors"
	"sync"
	"time"
	"ottergate/pkg/audit"
)

type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

type ProxyCircuitBreaker struct {
	mu              sync.Mutex
	state           CircuitState
	failures        int
	lastFailureTime time.Time
	threshold       int
	resetTimeout    time.Duration
	targetHost      string
}

func NewProxyCircuitBreaker(targetHost string) *ProxyCircuitBreaker {
	return &ProxyCircuitBreaker{
		state:        StateClosed,
		threshold:    5,
		resetTimeout: 10 * time.Second,
		targetHost:   targetHost,
	}
}

func (cb *ProxyCircuitBreaker) Execute(action func() error) error {
	cb.mu.Lock()
	now := time.Now()

	if cb.state == StateOpen {
		if now.Sub(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = StateHalfOpen
			audit.Logger.System(cb.targetHost + " Circuit Breaker transitioned to HALF_OPEN")
		} else {
			cb.mu.Unlock()
			return errors.New("Target Offline (Circuit Breaker OPEN)")
		}
	}
	cb.mu.Unlock()

	err := action()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()
		if cb.failures >= cb.threshold && cb.state != StateOpen {
			cb.state = StateOpen
			audit.Logger.System(cb.targetHost + " Circuit Breaker transitioned to OPEN")
		}
		return err
	}

	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.failures = 0
		audit.Logger.System(cb.targetHost + " Circuit Breaker transitioned to CLOSED")
	}

	return nil
}
