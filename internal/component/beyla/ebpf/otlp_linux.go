//go:build (linux && arm64) || (linux && amd64)

package beyla

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"github.com/grafana/alloy/internal/component/otelcol"
	"github.com/grafana/alloy/internal/runtime/logging/level"
)

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
//
// The receiver runs entirely on the Run goroutine (start/stop), and the workers and
// handlers capture the queue and output consumers, so the otlp* fields need no locking.
func (c *Component) startOTLPReceiver() error {
	output := c.args.Output
	if output == nil || (len(output.Traces) == 0 && len(output.Metrics) == 0) {
		return nil
	}

	addr := abstractSocketAddr("otlp", c.opts.ID)
	lis, err := net.Listen("unix", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on OTLP receiver UDS %q: %w", addr, err)
	}

	queue := make(chan otlpItem, otlpQueueCapacity)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	for i := 0; i < otlpWorkers; i++ {
		c.otlpWorkersWG.Add(1)
		go c.otlpWorker(workerCtx, queue, output)
	}

	level.Info(c.opts.Logger).Log("msg", "starting OTLP receiver", "addr", addr)

	mux := http.NewServeMux()
	if len(output.Traces) > 0 {
		mux.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
			c.enqueueOTLP(w, r, queue, true)
		})
	}
	if len(output.Metrics) > 0 {
		mux.HandleFunc("/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
			c.enqueueOTLP(w, r, queue, false)
		})
	}

	server := &http.Server{Handler: mux}

	c.otlpReceiverAddr = addr
	c.otlpQueue = queue
	c.otlpWorkerCancel = workerCancel
	c.otlpServer = server

	go func() {
		if err := server.Serve(lis); err != nil && err != http.ErrServerClosed {
			level.Error(c.opts.Logger).Log("msg", "OTLP receiver server error", "err", err)
		}
	}()

	return nil
}

func (c *Component) stopOTLPReceiver() {
	server := c.otlpServer
	queue := c.otlpQueue
	cancel := c.otlpWorkerCancel

	c.otlpServer = nil
	c.otlpQueue = nil
	c.otlpWorkerCancel = nil

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

func (c *Component) enqueueOTLP(w http.ResponseWriter, r *http.Request, queue chan otlpItem, isTraces bool) {
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

func (c *Component) otlpWorker(ctx context.Context, queue <-chan otlpItem, output *otelcol.ConsumerArguments) {
	defer c.otlpWorkersWG.Done()
	for item := range queue {
		if item.isTraces {
			c.consumeTraces(ctx, item, output.Traces)
		} else {
			c.consumeMetrics(ctx, item, output.Metrics)
		}
	}
}

func (c *Component) consumeMetrics(ctx context.Context, item otlpItem, consumers []otelcol.Consumer) {
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
	for _, consumer := range consumers {
		if err := consumer.ConsumeMetrics(ctx, metrics); err != nil {
			level.Error(c.opts.Logger).Log("msg", "failed to forward metrics to consumer", "err", err)
			return
		}
	}
}

func (c *Component) consumeTraces(ctx context.Context, item otlpItem, consumers []otelcol.Consumer) {
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
	for _, consumer := range consumers {
		if err := consumer.ConsumeTraces(ctx, traces); err != nil {
			level.Error(c.opts.Logger).Log("msg", "failed to forward traces to consumer", "err", err)
			return
		}
	}
}
