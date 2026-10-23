// Package main is the entry point for the Q-EDR Linux Endpoint Telemetry Collector.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Qapler/Q-EDR/edge-agent/internal/collector"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/filesystem"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/ipc"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/network"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/process"
	"github.com/Qapler/Q-EDR/edge-agent/internal/config"
	"github.com/Qapler/Q-EDR/edge-agent/internal/metrics"
	"github.com/Qapler/Q-EDR/edge-agent/internal/output"
)

const version = "0.1.0"

func main() {
	// Diagnostic logs ALWAYS go to stderr so they never contaminate stdout JSONL
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	cfg, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing configuration: %v\n", err)
		os.Exit(1)
	}

	log.Printf("[main] Q-EDR Endpoint Telemetry Collector v%s starting...", version)
	log.Printf("[main] Configuration: Output=%s, LogLevel=%s, Process=%v, Network=%v, IPC=%v, Filesystem=%v",
		cfg.OutputPath, cfg.LogLevel, cfg.EnableProcess, cfg.EnableNetwork, cfg.EnableIPC, cfg.EnableFilesystem)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals (SIGINT, SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[main] Received signal %v, initiating graceful shutdown...", sig)
		cancel()
	}()

	// Initialize metrics counters
	counters := metrics.NewCounters()

	// Initialize output JSONL writer
	writer, err := output.NewWriter(cfg.OutputPath, cfg.BufferSize)
	if err != nil {
		log.Fatalf("[main] Failed to initialize output writer: %v", err)
	}
	defer writer.Close()

	// Initialize collector manager
	mgr := collector.NewManager(cfg, writer, counters)

	// Register enabled collectors
	if cfg.EnableProcess {
		mgr.Register(process.New(cfg, counters))
	}
	if cfg.EnableNetwork {
		mgr.Register(network.New(cfg, counters))
	}
	if cfg.EnableIPC {
		mgr.Register(ipc.New(cfg, counters))
	}
	if cfg.EnableFilesystem {
		mgr.Register(filesystem.New(cfg, counters))
	}

	// Periodic metrics logging
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := counters.TakeSnapshot()
				written, dropped := writer.Stats()
				log.Printf("[metrics] %s | Output: written=%d dropped=%d", snap.String(), written, dropped)
			}
		}
	}()

	// Run collector manager (blocks until shutdown)
	if err := mgr.Run(ctx); err != nil {
		log.Fatalf("[main] Collector run failed: %v", err)
	}

	written, dropped := writer.Stats()
	log.Printf("[main] Collector shutdown complete. Total written: %d, dropped: %d", written, dropped)
}
