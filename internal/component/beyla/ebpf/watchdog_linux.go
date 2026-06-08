//go:build (linux && arm64) || (linux && amd64)

package beyla

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/grafana/alloy/internal/runtime/logging/level"
)

// watchdogLoop periodically probes the Beyla subprocess and kills it (by returning
// an error, which the monitor turns into a restart) once it has been unresponsive
// for failuresBeforeKill consecutive probes. Successful probes mark the subprocess
// ready and, after enough of them, reset the restart backoff.
func (c *Component) watchdogLoop(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Beyla loads eBPF programs before opening its Prometheus port (~15-20s).
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(20 * time.Second):
	}

	consecutiveSuccesses := 0
	consecutiveFailures := 0
	const successesNeededToResetBackoff = 3
	const failuresBeforeKill = 5

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.probeSubprocess(); err != nil {
				consecutiveFailures++
				level.Warn(c.opts.Logger).Log("msg", "subprocess probe failed", "err", err, "consecutive_failures", consecutiveFailures)
				c.health.SetUnhealthy(err)
				consecutiveSuccesses = 0
				if consecutiveFailures >= failuresBeforeKill {
					return fmt.Errorf("subprocess unresponsive after %d consecutive probe failures", consecutiveFailures)
				}
			} else {
				consecutiveFailures = 0
				c.subprocess.SetReady(true)
				c.health.SetHealthy()
				consecutiveSuccesses++

				if consecutiveSuccesses >= successesNeededToResetBackoff {
					if c.subprocess.ResetBackoffIfElevated() {
						level.Debug(c.opts.Logger).Log("msg", "resetting restart backoff after successful probes")
					}
					consecutiveSuccesses = 0
				}
			}
		}
	}
}

// probeSubprocess issues a single request to Beyla's /healthz endpoint over its
// abstract Unix socket, returning an error if it is unreachable or unhealthy.
func (c *Component) probeSubprocess() error {
	addr := c.subprocess.HealthAddr()

	if addr == "" {
		return fmt.Errorf("subprocess not started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Host is nominal — the DialContext below dials Beyla's abstract socket.
	req, err := http.NewRequestWithContext(ctx, "GET", "http://beyla/healthz", nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", addr)
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("subprocess not responding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subprocess returned status %d", resp.StatusCode)
	}

	return nil
}
