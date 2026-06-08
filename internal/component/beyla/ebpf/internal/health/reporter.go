// Package health holds the thread-safe health state reported to the Alloy
// runtime. The wrapped value is unexported, so callers must go through the
// locking methods below.
package health

import (
	"sync"
	"time"

	"github.com/grafana/alloy/internal/component"
)

// Reporter tracks the component's current health.
type Reporter struct {
	mu     sync.RWMutex
	health component.Health
}

// New returns a Reporter with zero-value (unknown) health.
func New() *Reporter {
	return &Reporter{}
}

// Current returns the current health.
func (r *Reporter) Current() component.Health {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.health
}

// SetHealthy marks the component healthy.
func (r *Reporter) SetHealthy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = component.Health{
		Health:     component.HealthTypeHealthy,
		UpdateTime: time.Now(),
	}
}

// SetUnhealthy marks the component unhealthy with the given error.
func (r *Reporter) SetUnhealthy(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = component.Health{
		Health:     component.HealthTypeUnhealthy,
		Message:    err.Error(),
		UpdateTime: time.Now(),
	}
}
