package collector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Qapler/Q-EDR/edge-agent/internal/config"
	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
	"github.com/Qapler/Q-EDR/edge-agent/internal/metrics"
	"github.com/Qapler/Q-EDR/edge-agent/internal/output"
)

// Manager orchestrates all registered telemetry collectors.
type Manager struct {
	cfg        *config.Config
	collectors []Collector
	writer     *output.Writer
	counters   *metrics.Counters
	events     chan *envelope.Event
	wg         sync.WaitGroup
}

// NewManager creates a new collector manager.
func NewManager(cfg *config.Config, writer *output.Writer, counters *metrics.Counters) *Manager {
	return &Manager{
		cfg:      cfg,
		writer:   writer,
		counters: counters,
		events:   make(chan *envelope.Event, cfg.BufferSize),
	}
}

// Register adds a collector to the manager.
func (m *Manager) Register(c Collector) {
	m.collectors = append(m.collectors, c)
}

// Run starts all registered collectors and the event writer loop.
// It blocks until ctx is cancelled, then gracefully shuts down.
func (m *Manager) Run(ctx context.Context) error {
	if len(m.collectors) == 0 {
		return fmt.Errorf("no collectors registered")
	}

	// Start the event writer goroutine.
	m.wg.Add(1)
	go m.writerLoop(ctx)

	// Perform startup snapshots if enabled.
	if m.cfg.SnapshotOnStartup {
		m.runSnapshots(ctx)
	}

	// Start all event-driven collectors.
	for _, c := range m.collectors {
		c := c
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			log.Printf("[manager] starting collector: %s", c.Name())
			if err := c.Start(ctx, m.events); err != nil {
				if ctx.Err() == nil {
					log.Printf("[manager] collector %s error: %v", c.Name(), err)
					m.counters.RecordError()
				}
			}
			log.Printf("[manager] collector %s stopped", c.Name())
		}()
	}

	// Start periodic snapshot loop if configured.
	if m.cfg.SnapshotInterval > 0 {
		m.wg.Add(1)
		go m.snapshotLoop(ctx)
	}

	// Wait for context cancellation.
	<-ctx.Done()
	log.Printf("[manager] shutdown signal received, stopping collectors...")

	// Stop all collectors.
	for _, c := range m.collectors {
		if err := c.Stop(); err != nil {
			log.Printf("[manager] error stopping %s: %v", c.Name(), err)
		}
	}

	// Close events channel and wait for writer to drain.
	close(m.events)
	m.wg.Wait()

	// Flush output.
	if err := m.writer.Flush(); err != nil {
		log.Printf("[manager] error flushing output: %v", err)
	}

	// Log final stats.
	snap := m.counters.TakeSnapshot()
	log.Printf("[manager] final stats: %s", snap.String())

	return nil
}

// writerLoop reads events from the channel and writes them as JSONL.
func (m *Manager) writerLoop(ctx context.Context) {
	defer m.wg.Done()

	flushTicker := time.NewTicker(1 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case evt, ok := <-m.events:
			if !ok {
				return // Channel closed.
			}
			b, err := evt.Marshal()
			if err != nil {
				log.Printf("[writer] marshal error for %s: %v", evt.EventType, err)
				m.counters.RecordError()
				continue
			}
			if err := m.writer.WriteEvent(b); err != nil {
				log.Printf("[writer] write error: %v", err)
				m.counters.RecordDrop(categoryFromEventType(evt.EventType))
				continue
			}
			m.counters.RecordEvent(categoryFromEventType(evt.EventType))

		case <-flushTicker.C:
			if err := m.writer.Flush(); err != nil {
				log.Printf("[writer] flush error: %v", err)
			}
		}
	}
}

// snapshotLoop runs periodic snapshots at the configured interval.
func (m *Manager) snapshotLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.cfg.SnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runSnapshots(ctx)
		}
	}
}

// runSnapshots calls Snapshot on all collectors that support it.
func (m *Manager) runSnapshots(ctx context.Context) {
	for _, c := range m.collectors {
		if sc, ok := c.(SnapshotCollector); ok {
			log.Printf("[manager] running snapshot: %s", c.Name())
			if err := sc.Snapshot(ctx, m.events); err != nil {
				log.Printf("[manager] snapshot error for %s: %v", c.Name(), err)
				m.counters.RecordError()
			}
		}
	}
}

// categoryFromEventType extracts the category prefix from an event type.
// e.g. "process.exec" -> "process", "network.connect" -> "network".
func categoryFromEventType(eventType string) string {
	for i, c := range eventType {
		if c == '.' {
			return eventType[:i]
		}
	}
	return eventType
}
