package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotatingWriter is a thread-safe io.WriteCloser that writes to a file and
// automatically rotates the log file once it exceeds maxSize bytes.
// It maintains at most maxBackups historical log files (e.g. log.1, log.2).
type RotatingWriter struct {
	mu         sync.Mutex
	filePath   string
	maxSize    int64
	maxBackups int
	currentSize int64
	file       *os.File
}

// NewRotatingWriter creates and initializes a RotatingWriter.
func NewRotatingWriter(filePath string, maxSize int64, maxBackups int) (*RotatingWriter, error) {
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // default 10MB
	}
	if maxBackups <= 0 {
		maxBackups = 1 // default 1 backup
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	w := &RotatingWriter{
		filePath:   filePath,
		maxSize:    maxSize,
		maxBackups: maxBackups,
	}

	if err := w.openExistingOrNew(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) openExistingOrNew() error {
	fi, err := os.Stat(w.filePath)
	if err == nil {
		w.currentSize = fi.Size()
		f, err := os.OpenFile(w.filePath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		w.file = f
		return nil
	}

	f, err := os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	w.file = f
	w.currentSize = 0
	return nil
}

// Write writes data to the current file, rotating if the write causes it to exceed maxSize.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	writeLen := int64(len(p))
	if w.currentSize+writeLen > w.maxSize && w.currentSize > 0 {
		if err := w.rotate(); err != nil {
			// Fallback: continue writing even if rotate fails
			fmt.Fprintf(os.Stderr, "vproxy: rotating writer failed: %v\n", err)
		}
	}

	if w.file == nil {
		if err := w.openExistingOrNew(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.currentSize += int64(n)
	return n, err
}

func (w *RotatingWriter) rotate() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}

	// Remove the oldest backup if exists
	oldest := fmt.Sprintf("%s.%d", w.filePath, w.maxBackups)
	_ = os.Remove(oldest)

	// Shift existing backups: log.(N-1) -> log.N
	for i := w.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.filePath, i)
		dst := fmt.Sprintf("%s.%d", w.filePath, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}

	// Rename current file to log.1
	firstBackup := fmt.Sprintf("%s.1", w.filePath)
	_ = os.Rename(w.filePath, firstBackup)

	return w.openExistingOrNew()
}

// Close closes the underlying active log file.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}
