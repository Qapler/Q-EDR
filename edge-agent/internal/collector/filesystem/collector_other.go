//go:build !linux

package filesystem

import (
	"context"
	"fmt"

	"github.com/Qapler/Q-EDR/edge-agent/internal/config"
	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
	"github.com/Qapler/Q-EDR/edge-agent/internal/metrics"
)

// Collector is a stub for non-Linux platforms.
type Collector struct{}

func New(cfg *config.Config, counters *metrics.Counters) *Collector {
	return &Collector{}
}

func (c *Collector) Name() string { return "filesystem" }

func (c *Collector) Start(ctx context.Context, events chan<- *envelope.Event) error {
	return fmt.Errorf("filesystem collector requires Linux with eBPF support")
}

func (c *Collector) Stop() error { return nil }

func (c *Collector) Snapshot(ctx context.Context, events chan<- *envelope.Event) error {
	return fmt.Errorf("filesystem snapshot requires Linux")
}
