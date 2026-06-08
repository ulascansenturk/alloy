// Package subprocess holds the thread-safe state of the managed Beyla
// subprocess. All fields are unexported, so callers can only read or mutate them
// through the methods below, each of which takes the lock. This makes the
// locking discipline a compiler-enforced invariant rather than a convention.
package subprocess

import (
	"os/exec"
	"sync"
	"time"
)

// MaxRestarts is the number of consecutive restarts before the caller should give up.
const MaxRestarts = 10

// Handle is a thread-safe handle to the running Beyla subprocess.
type Handle struct {
	mu sync.Mutex

	exePath     string
	exeClose    func()
	configPath  string
	configClose func()
	port        int
	addr        string
	profilePort int
	healthAddr  string
	cmd         *exec.Cmd
	ready       bool

	restartCount int
	backoff      time.Duration
}

// New returns a Handle with the restart backoff initialized.
func New() *Handle {
	return &Handle{backoff: time.Second}
}

// SetBinary records the extracted Beyla binary path and its memfd closer.
func (h *Handle) SetBinary(path string, closeFn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.exePath = path
	h.exeClose = closeFn
}

// SetListen records the subprocess HTTP port and address.
func (h *Handle) SetListen(port int, addr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.port = port
	h.addr = addr
}

// SetProfilePort records the Beyla pprof port (0 when pprof is disabled).
func (h *Handle) SetProfilePort(port int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.profilePort = port
}

// SetHealthAddr records the abstract UDS address of Beyla's health endpoint.
func (h *Handle) SetHealthAddr(addr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.healthAddr = addr
}

// SetConfig records the config file path and its memfd closer.
func (h *Handle) SetConfig(path string, closeFn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.configPath = path
	h.configClose = closeFn
}

// Launch returns the values needed to start the subprocess.
func (h *Handle) Launch() (exePath, configPath string, port, profilePort int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.exePath, h.configPath, h.port, h.profilePort
}

// SetCmd records the running command.
func (h *Handle) SetCmd(cmd *exec.Cmd) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cmd = cmd
}

// CloseBinary runs and clears the binary memfd closer, if set.
func (h *Handle) CloseBinary() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.exeClose != nil {
		h.exeClose()
		h.exeClose = nil
	}
}

// Pid returns the subprocess PID and whether it is running.
func (h *Handle) Pid() (int, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd == nil || h.cmd.Process == nil {
		return 0, false
	}
	return h.cmd.Process.Pid, true
}

// Port returns the subprocess HTTP port.
func (h *Handle) Port() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.port
}

// ProxyTarget returns the values the HTTP handler needs to reverse-proxy a request.
func (h *Handle) ProxyTarget() (addr string, profilePort int, ready bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addr, h.profilePort, h.ready
}

// HealthAddr returns the abstract UDS address of Beyla's health endpoint.
func (h *Handle) HealthAddr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.healthAddr
}

// SetReady records whether the subprocess has passed a health check.
func (h *Handle) SetReady(ready bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = ready
}

// Reset runs the memfd closers and clears the per-run subprocess state. The port,
// address and command are left in place so the HTTP handler keeps reporting
// "initializing" rather than "not started" across a restart.
func (h *Handle) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.exeClose != nil {
		h.exeClose()
		h.exeClose = nil
	}
	if h.configClose != nil {
		h.configClose()
		h.configClose = nil
	}
	h.exePath = ""
	h.configPath = ""
	h.profilePort = 0
	h.healthAddr = ""
	h.ready = false
}

// RecordStart bumps the restart counter and returns the count before the bump.
func (h *Handle) RecordStart() (prior int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	prior = h.restartCount
	h.restartCount++
	return prior
}

// ResetRestartTracking clears the restart counter and backoff.
func (h *Handle) ResetRestartTracking() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.restartCount = 0
	h.backoff = time.Second
}

// ResetBackoffIfElevated clears restart tracking when the backoff has grown past
// its initial value, reporting whether it did so.
func (h *Handle) ResetBackoffIfElevated() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.backoff <= time.Second {
		return false
	}
	h.backoff = time.Second
	h.restartCount = 0
	return true
}

// NextBackoff returns the current backoff and restart count, then doubles the
// backoff (capped at 30s) for next time. ok is false once MaxRestarts is reached.
func (h *Handle) NextBackoff() (backoff time.Duration, count int, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.restartCount >= MaxRestarts {
		return 0, h.restartCount, false
	}
	backoff = h.backoff
	h.backoff = min(h.backoff*2, 30*time.Second)
	return backoff, h.restartCount, true
}
