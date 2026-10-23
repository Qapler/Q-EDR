// Package collector defines the interface for telemetry collectors and provides
// the manager that orchestrates all category-specific collectors.
package collector

import (
	"context"

	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
)

// Collector is the interface that all telemetry category collectors implement.
type Collector interface {
	// Name returns the collector's category name (e.g. "process", "network").
	Name() string

	// Start begins collecting telemetry events and sending them to the events channel.
	// It blocks until ctx is cancelled or a fatal error occurs.
	// Events must be fully populated with envelope metadata before being sent.
	Start(ctx context.Context, events chan<- *envelope.Event) error

	// Stop gracefully stops the collector and releases kernel resources.
	Stop() error
}

// SnapshotCollector extends Collector with snapshot capability.
type SnapshotCollector interface {
	Collector

	// Snapshot performs a point-in-time inventory scan and sends snapshot events.
	Snapshot(ctx context.Context, events chan<- *envelope.Event) error
}
