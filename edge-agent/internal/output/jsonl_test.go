package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterStdout(t *testing.T) {
	// NewWriter with "-" should not error.
	w, err := NewWriter("-", 16)
	if err != nil {
		t.Fatalf("NewWriter('-') error: %v", err)
	}
	defer w.Close()
}

func TestWriterFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-output.jsonl")

	w, err := NewWriter(path, 16)
	if err != nil {
		t.Fatalf("NewWriter(%q) error: %v", path, err)
	}

	// Write a JSON event.
	event := map[string]string{"test": "value"}
	b, _ := json.Marshal(event)
	if err := w.WriteEvent(b); err != nil {
		t.Fatalf("WriteEvent error: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Read back and verify.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("invalid JSON line: %v", err)
	}
	if parsed["test"] != "value" {
		t.Errorf("parsed[test] = %q, want %q", parsed["test"], "value")
	}
}

func TestWriterMultipleEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.jsonl")

	w, err := NewWriter(path, 16)
	if err != nil {
		t.Fatalf("NewWriter error: %v", err)
	}

	for i := 0; i < 100; i++ {
		event := map[string]int{"i": i}
		b, _ := json.Marshal(event)
		if err := w.WriteEvent(b); err != nil {
			t.Fatalf("WriteEvent(%d) error: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 100 {
		t.Fatalf("expected 100 lines, got %d", len(lines))
	}

	// Each line must be valid JSON.
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %q", i, line)
		}
	}
}

func TestWriterStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.jsonl")

	w, err := NewWriter(path, 16)
	if err != nil {
		t.Fatalf("NewWriter error: %v", err)
	}

	for i := 0; i < 10; i++ {
		b, _ := json.Marshal(map[string]int{"i": i})
		w.WriteEvent(b)
	}
	w.Close()

	written, dropped := w.Stats()
	if written != 10 {
		t.Errorf("written = %d, want 10", written)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

func TestWriterClosedDrops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "closed.jsonl")

	w, err := NewWriter(path, 16)
	if err != nil {
		t.Fatalf("NewWriter error: %v", err)
	}
	w.Close()

	// Writing after close should fail.
	b, _ := json.Marshal(map[string]string{"test": "after-close"})
	err = w.WriteEvent(b)
	if err == nil {
		t.Error("WriteEvent after Close should return error")
	}

	_, dropped := w.Stats()
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
}

func TestWriterOneJSONPerLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jsonl.jsonl")

	w, err := NewWriter(path, 16)
	if err != nil {
		t.Fatalf("NewWriter error: %v", err)
	}

	events := []map[string]interface{}{
		{"type": "process.exec", "pid": 1},
		{"type": "network.connect", "port": 443},
		{"type": "filesystem.open", "path": "/etc/passwd"},
	}

	for _, evt := range events {
		b, _ := json.Marshal(evt)
		w.WriteEvent(b)
	}
	w.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	// Verify each line is exactly one valid JSON object.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %q", lineNum, line)
		}
		// Verify it's a single JSON object (not multiple).
		dec := json.NewDecoder(strings.NewReader(line))
		var obj interface{}
		if err := dec.Decode(&obj); err != nil {
			t.Errorf("line %d decode error: %v", lineNum, err)
		}
		// There should be nothing left after the first object.
		if dec.More() {
			t.Errorf("line %d contains more than one JSON object", lineNum)
		}
		lineNum++
	}

	if lineNum != 3 {
		t.Errorf("expected 3 lines, got %d", lineNum)
	}
}
