// Package config defines the collector's runtime configuration and CLI parsing.
package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds the collector's runtime configuration.
type Config struct {
	// Output destination: "" or "-" for stdout, otherwise file path.
	OutputPath string

	// LogLevel controls diagnostic log verbosity: "debug", "info", "warn", "error".
	LogLevel string

	// Category toggles — each can be independently enabled/disabled.
	EnableProcess    bool
	EnableNetwork    bool
	EnableIPC        bool
	EnableFilesystem bool

	// SnapshotInterval controls how often inventory snapshots are taken.
	// Zero disables periodic snapshots (only startup snapshot is taken).
	SnapshotInterval time.Duration

	// SnapshotOnStartup controls whether an inventory snapshot is taken at startup.
	SnapshotOnStartup bool

	// RedactCmdline omits command-line arguments from process events.
	RedactCmdline bool

	// RedactFilePaths omits full file paths from filesystem events (retains basename).
	RedactFilePaths bool

	// BufferSize is the number of events buffered before writing (0 = write immediately).
	BufferSize int

	// MaxEventRate is the maximum events per second per category (0 = unlimited).
	MaxEventRate int

	// FilesystemFilterPaths limits filesystem monitoring to these path prefixes.
	// Empty means monitor all paths.
	FilesystemFilterPaths []string

	// ShowVersion prints version info and exits.
	ShowVersion bool

	// ShowHelp prints help and exits.
	ShowHelp bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		OutputPath:        "-",
		LogLevel:          "info",
		EnableProcess:     true,
		EnableNetwork:     true,
		EnableIPC:         true,
		EnableFilesystem:  true,
		SnapshotInterval:  60 * time.Second,
		SnapshotOnStartup: true,
		RedactCmdline:     false,
		RedactFilePaths:   false,
		BufferSize:        256,
		MaxEventRate:      0,
	}
}

// ParseFlags parses command-line flags into a Config.
func ParseFlags() (*Config, error) {
	cfg := DefaultConfig()

	fs := flag.NewFlagSet("q-edr-collector", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&cfg.OutputPath, "output", cfg.OutputPath,
		"Output destination: '-' for stdout, or a file path for JSONL output")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel,
		"Log level: debug, info, warn, error")
	fs.BoolVar(&cfg.EnableProcess, "process", cfg.EnableProcess,
		"Enable process telemetry collection")
	fs.BoolVar(&cfg.EnableNetwork, "network", cfg.EnableNetwork,
		"Enable network telemetry collection")
	fs.BoolVar(&cfg.EnableIPC, "ipc", cfg.EnableIPC,
		"Enable IPC telemetry collection")
	fs.BoolVar(&cfg.EnableFilesystem, "filesystem", cfg.EnableFilesystem,
		"Enable filesystem telemetry collection")
	fs.DurationVar(&cfg.SnapshotInterval, "snapshot-interval", cfg.SnapshotInterval,
		"Interval between inventory snapshots (0 to disable periodic snapshots)")
	fs.BoolVar(&cfg.SnapshotOnStartup, "snapshot-on-startup", cfg.SnapshotOnStartup,
		"Take an inventory snapshot at startup")
	fs.BoolVar(&cfg.RedactCmdline, "redact-cmdline", cfg.RedactCmdline,
		"Redact command-line arguments from process events")
	fs.BoolVar(&cfg.RedactFilePaths, "redact-file-paths", cfg.RedactFilePaths,
		"Redact full file paths (retain basename only)")
	fs.IntVar(&cfg.BufferSize, "buffer-size", cfg.BufferSize,
		"Number of events to buffer before writing (0 = write immediately)")
	fs.IntVar(&cfg.MaxEventRate, "max-event-rate", cfg.MaxEventRate,
		"Maximum events per second per category (0 = unlimited)")
	fs.BoolVar(&cfg.ShowVersion, "version", false,
		"Show version information and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, err
	}

	if cfg.ShowVersion {
		fmt.Fprintf(os.Stderr, "q-edr-linux-collector v0.1.0\n")
		os.Exit(0)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the configuration for invalid values.
func (c *Config) Validate() error {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		// OK
	default:
		return fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", c.LogLevel)
	}

	if c.BufferSize < 0 {
		return fmt.Errorf("buffer-size must be >= 0, got %d", c.BufferSize)
	}
	if c.MaxEventRate < 0 {
		return fmt.Errorf("max-event-rate must be >= 0, got %d", c.MaxEventRate)
	}
	if c.SnapshotInterval < 0 {
		return fmt.Errorf("snapshot-interval must be >= 0, got %v", c.SnapshotInterval)
	}

	if !c.EnableProcess && !c.EnableNetwork && !c.EnableIPC && !c.EnableFilesystem {
		return fmt.Errorf("at least one telemetry category must be enabled")
	}

	return nil
}

// AnyCategoryEnabled returns true if at least one telemetry category is enabled.
func (c *Config) AnyCategoryEnabled() bool {
	return c.EnableProcess || c.EnableNetwork || c.EnableIPC || c.EnableFilesystem
}
