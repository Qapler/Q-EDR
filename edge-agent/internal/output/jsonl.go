// Package output provides JSONL (JSON Lines) writing with buffering and backpressure.
//
// Each telemetry event is written as exactly one JSON object per line to either
// stdout or a specified file. Diagnostic logs are never mixed with JSONL output.
package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// Writer writes JSONL output to a destination with buffering and drop tracking.
type Writer struct {
	mu         sync.Mutex
	w          *bufio.Writer
	closer     io.Closer // Non-nil if we opened a file.
	written    atomic.Uint64
	dropped    atomic.Uint64
	bufferSize int
	closed     bool
}

// NewWriter creates a JSONL writer.
// If path is "" or "-", writes to stdout.
// Otherwise, opens the file for append.
func NewWriter(path string, bufferSize int) (*Writer, error) {
	var dest io.Writer
	var closer io.Closer

	if path == "" || path == "-" {
		dest = os.Stdout
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("open output file %q: %w", path, err)
		}
		dest = f
		closer = f
	}

	if bufferSize <= 0 {
		bufferSize = 4096
	}

	return &Writer{
		w:          bufio.NewWriterSize(dest, bufferSize*256), // Approximate bytes per event.
		closer:     closer,
		bufferSize: bufferSize,
	}, nil
}

// WriteEvent writes a single pre-serialized JSON event as one JSONL line.
// It appends a newline after the JSON bytes.
// Returns an error if the write fails; callers should count drops.
func (w *Writer) WriteEvent(jsonBytes []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		w.dropped.Add(1)
		return fmt.Errorf("writer is closed")
	}

	// Write JSON bytes + newline as a single JSONL record.
	if _, err := w.w.Write(jsonBytes); err != nil {
		w.dropped.Add(1)
		return fmt.Errorf("write event: %w", err)
	}
	if err := w.w.WriteByte('\n'); err != nil {
		w.dropped.Add(1)
		return fmt.Errorf("write newline: %w", err)
	}

	w.written.Add(1)
	return nil
}

// Flush flushes the internal buffer to the underlying writer.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Flush()
}

// Close flushes and closes the writer. Safe to call multiple times.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true

	if err := w.w.Flush(); err != nil {
		return fmt.Errorf("flush on close: %w", err)
	}
	if w.closer != nil {
		return w.closer.Close()
	}
	return nil
}

// Stats returns the number of events written and dropped.
func (w *Writer) Stats() (written, dropped uint64) {
	return w.written.Load(), w.dropped.Load()
}
