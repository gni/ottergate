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
	trialInFlight   bool
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
			cb.trialInFlight = true
			audit.Logger.System(cb.targetHost + " Circuit Breaker transitioned to HALF_OPEN (Trial State Init)")
		} else {
			cb.mu.Unlock()
			return errors.New("Target Offline (Circuit Breaker OPEN)")
		}
	} else if cb.state == StateHalfOpen {
		if cb.trialInFlight {
			cb.mu.Unlock()
			return errors.New("Target Offline (Circuit Breaker HALF_OPEN Trial In-Flight)")
		}
		cb.trialInFlight = true
	}
	cb.mu.Unlock()

	err := action()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()
		cb.state = StateOpen
		cb.trialInFlight = false
		audit.Logger.System(cb.targetHost + " Circuit Breaker transitioned to OPEN due to trial failure")
		return err
	}

	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.failures = 0
		cb.trialInFlight = false
		audit.Logger.System(cb.targetHost + " Circuit Breaker transitioned to CLOSED")
	}

	return nil
}