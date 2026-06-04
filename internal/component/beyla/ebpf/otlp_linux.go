//go:build (linux && arm64) || (linux && amd64)

package beyla

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"github.com/grafana/alloy/internal/runtime/logging/level"
)

// TODO(diagnostic): temporary self-probe to catch transient connect:ECONNREFUSED
// on the OTLP receiver's own socket. Remove once the UDS refusal is root-caused.
const otlpSelfProbeInterval = 50 * time.Millisecond

// Receiver handlers hand requests off to a bounded queue drained by a fixed worker
// pool, so the slow downstream consume never blocks the accept path. This keeps
// handlers fast, lets Beyla reuse its keep-alive connections, and turns sustained
// backpressure into an explicit 503 instead of a UDS accept-backlog overflow.
const (
	otlpQueueCapacity = 256
	otlpWorkers       = 4
)

// otlpItem is a request body handed from a receiver handler to a worker.
type otlpItem struct {
	isTraces    bool
	body        []byte
	contentType string
}

// startOTLPReceiver starts an HTTP server to receive OTLP traces and/or metrics from Beyla
// and forwards them to the configured Output consumers. Listens on a Linux abstract Unix
// socket so the Beyla↔Alloy hop avoids the TCP loopback path entirely (no conntrack,
// no ephemeral port churn).
func (c *Component) startOTLPReceiver() error {
	if c.args.Output == nil || (len(c.args.Output.Traces) == 0 && len(c.args.Output.Metrics) == 0) {
		return nil
	}

	addr := abstractSocketAddr("otlp", c.opts.ID)
	lis, err := net.Listen("unix", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on OTLP receiver UDS %q: %w", addr, err)
	}

	c.mut.Lock()
	c.otlpReceiverAddr = addr
	c.otlpQueue = make(chan otlpItem, otlpQueueCapacity)
	c.otlpWorkerCtx, c.otlpWorkerCancel = context.WithCancel(context.Background())
	for i := 0; i < otlpWorkers; i++ {
		c.otlpWorkersWG.Add(1)
		go c.otlpWorker(c.otlpWorkerCtx, c.otlpQueue)
	}
	c.otlpWorkersWG.Add(1)
	go c.otlpSelfProbe(c.otlpWorkerCtx, addr)
	c.mut.Unlock()

	level.Info(c.opts.Logger).Log("msg", "starting OTLP receiver", "addr", addr)

	mux := http.NewServeMux()
	if len(c.args.Output.Traces) > 0 {
		mux.HandleFunc("/v1/traces", c.handleOTLPTraces)
	}
	if len(c.args.Output.Metrics) > 0 {
		mux.HandleFunc("/v1/metrics", c.handleOTLPMetrics)
	}

	server := &http.Server{
		Handler: mux,
	}

	c.mut.Lock()
	c.otlpServer = server
	c.mut.Unlock()

	go func() {
		if err := server.Serve(lis); err != nil && err != http.ErrServerClosed {
			level.Error(c.opts.Logger).Log("msg", "OTLP receiver server error", "err", err)
		}
	}()

	return nil
}

func (c *Component) stopOTLPReceiver() {
	c.mut.Lock()
	server := c.otlpServer
	queue := c.otlpQueue
	cancel := c.otlpWorkerCancel
	c.otlpServer = nil
	c.otlpQueue = nil
	c.otlpWorkerCancel = nil
	c.mut.Unlock()

	if server != nil {
		level.Debug(c.opts.Logger).Log("msg", "stopping OTLP receiver")
		ctx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(ctx); err != nil {
			level.Warn(c.opts.Logger).Log("msg", "error shutting down OTLP receiver", "err", err)
		}
	}

	// After Shutdown returns no handler is running, so no goroutine can still
	// enqueue: it is safe to cancel in-flight consumes and close the queue.
	if cancel != nil {
		cancel()
	}
	if queue != nil {
		close(queue)
	}
	c.otlpWorkersWG.Wait()
}

func (c *Component) handleOTLPMetrics(w http.ResponseWriter, r *http.Request) {
	c.enqueueOTLP(w, r, false)
}

func (c *Component) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	c.enqueueOTLP(w, r, true)
}

func (c *Component) enqueueOTLP(w http.ResponseWriter, r *http.Request, isTraces bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to read OTLP request body", "err", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	c.mut.Lock()
	queue := c.otlpQueue
	c.mut.Unlock()

	if queue == nil {
		http.Error(w, "receiver not running", http.StatusServiceUnavailable)
		return
	}

	item := otlpItem{isTraces: isTraces, body: body, contentType: r.Header.Get("Content-Type")}
	select {
	case queue <- item:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	default:
		// Sustained downstream backpressure; 503 is retryable and Beyla's OTLP exporter honours it.
		level.Warn(c.opts.Logger).Log("msg", "OTLP receiver queue full, rejecting request", "is_traces", isTraces)
		http.Error(w, "receiver overloaded", http.StatusServiceUnavailable)
	}
}

func (c *Component) otlpWorker(ctx context.Context, queue <-chan otlpItem) {
	defer c.otlpWorkersWG.Done()
	for item := range queue {
		if item.isTraces {
			c.consumeTraces(ctx, item)
		} else {
			c.consumeMetrics(ctx, item)
		}
	}
}

func (c *Component) consumeMetrics(ctx context.Context, item otlpItem) {
	req := pmetricotlp.NewExportRequest()
	var err error
	if strings.Contains(item.contentType, "application/json") {
		err = req.UnmarshalJSON(item.body)
	} else {
		err = req.UnmarshalProto(item.body)
	}
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to unmarshal OTLP metrics", "err", err)
		return
	}

	metrics := req.Metrics()

	c.mut.Lock()
	consumers := c.args.Output.Metrics
	c.mut.Unlock()

	for _, consumer := range consumers {
		if err := consumer.ConsumeMetrics(ctx, metrics); err != nil {
			level.Error(c.opts.Logger).Log("msg", "failed to forward metrics to consumer", "err", err)
			return
		}
	}
}

func (c *Component) consumeTraces(ctx context.Context, item otlpItem) {
	req := ptraceotlp.NewExportRequest()
	var err error
	if strings.Contains(item.contentType, "application/json") {
		err = req.UnmarshalJSON(item.body)
	} else {
		err = req.UnmarshalProto(item.body)
	}
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "failed to unmarshal OTLP traces", "err", err)
		return
	}

	traces := req.Traces()

	c.mut.Lock()
	consumers := c.args.Output.Traces
	c.mut.Unlock()

	for _, consumer := range consumers {
		if err := consumer.ConsumeTraces(ctx, traces); err != nil {
			level.Error(c.opts.Logger).Log("msg", "failed to forward traces to consumer", "err", err)
			return
		}
	}
}

// otlpSelfProbe dials the receiver's own socket on a tight interval and logs any
// connect failure together with the listener's /proc/net/unix line, to catch the
// transient connect:ECONNREFUSED red-handed. Diagnostic only.
func (c *Component) otlpSelfProbe(ctx context.Context, addr string) {
	defer c.otlpWorkersWG.Done()

	// Logged from inside the goroutine so it only appears if the probe truly started.
	level.Info(c.opts.Logger).Log("msg", "OTLP self-probe started", "addr", addr, "interval", otlpSelfProbeInterval.String())

	ticker := time.NewTicker(otlpSelfProbeInterval)
	defer ticker.Stop()

	heartbeat := time.NewTicker(5 * time.Minute)
	defer heartbeat.Stop()

	var dials, failures uint64
	var d net.Dialer
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// Positive proof the probe is alive across the whole run; distinguishes
			// "saw nothing" from "died" when reading logs after the fact.
			level.Info(c.opts.Logger).Log("msg", "OTLP self-probe heartbeat", "dials", dials, "failures", failures)
		case <-ticker.C:
			dials++
			conn, err := d.DialContext(ctx, "unix", addr)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				failures++
				level.Warn(c.opts.Logger).Log(
					"msg", "OTLP self-probe dial failed",
					"addr", addr,
					"err", err,
					"proc_net_unix", procNetUnixFor(addr),
				)
				continue
			}
			_ = conn.Close()
		}
	}
}

// procNetUnixFor returns the /proc/net/unix lines mentioning addr (the listener and
// any live connections), so a probe failure captures the socket's kernel-visible state.
func procNetUnixFor(addr string) string {
	name := strings.TrimPrefix(addr, "@")
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	var matched []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, name) {
			matched = append(matched, strings.TrimSpace(line))
		}
	}
	if len(matched) == 0 {
		return "no matching socket"
	}
	return strings.Join(matched, " | ")
}
