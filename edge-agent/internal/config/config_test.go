package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.OutputPath != "-" {
		t.Errorf("expected default OutputPath '-', got %q", cfg.OutputPath)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got %q", cfg.LogLevel)
	}
	if !cfg.EnableProcess || !cfg.EnableNetwork || !cfg.EnableIPC || !cfg.EnableFilesystem {
		t.Errorf("expected all categories enabled by default")
	}
	if cfg.SnapshotInterval != 60*time.Second {
		t.Errorf("expected 60s snapshot interval, got %v", cfg.SnapshotInterval)
	}
	if !cfg.SnapshotOnStartup {
		t.Errorf("expected SnapshotOnStartup=true by default")
	}
	if cfg.BufferSize != 256 {
		t.Errorf("expected BufferSize=256, got %d", cfg.BufferSize)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid defaults",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "invalid log level",
			modify:  func(c *Config) { c.LogLevel = "verbose" },
			wantErr: true,
		},
		{
			name:    "negative buffer size",
			modify:  func(c *Config) { c.BufferSize = -1 },
			wantErr: true,
		},
		{
			name:    "negative max event rate",
			modify:  func(c *Config) { c.MaxEventRate = -5 },
			wantErr: true,
		},
		{
			name:    "negative snapshot interval",
			modify:  func(c *Config) { c.SnapshotInterval = -1 * time.Second },
			wantErr: true,
		},
		{
			name: "all categories disabled",
			modify: func(c *Config) {
				c.EnableProcess = false
				c.EnableNetwork = false
				c.EnableIPC = false
				c.EnableFilesystem = false
			},
			wantErr: true,
		},
		{
			name: "single category enabled is valid",
			modify: func(c *Config) {
				c.EnableProcess = true
				c.EnableNetwork = false
				c.EnableIPC = false
				c.EnableFilesystem = false
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAnyCategoryEnabled(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.AnyCategoryEnabled() {
		t.Errorf("expected true when all enabled")
	}

	cfg.EnableProcess = false
	cfg.EnableNetwork = false
	cfg.EnableIPC = false
	cfg.EnableFilesystem = false
	if cfg.AnyCategoryEnabled() {
		t.Errorf("expected false when all disabled")
	}

	cfg.EnableIPC = true
	if !cfg.AnyCategoryEnabled() {
		t.Errorf("expected true when IPC enabled")
	}
}
