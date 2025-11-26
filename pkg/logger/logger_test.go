package logger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// captureStderr captures stderr output for testing
func captureStderr(f func()) string {
	r, w, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	f()

	w.Close()
	os.Stderr = oldStderr
	return <-outC
}

func TestLogger_Concurrency(t *testing.T) {
	// This test mainly checks for race conditions using the race detector
	// Run with: go test -race ./pkg/logger/...
	l := NewLogger(2) // Very verbose

	var wg sync.WaitGroup
	concurrency := 100

	// We can't easily capture stderr in parallel tests without a lot of hacking,
	// so we just focus on ensuring no panics or race conditions occur.
	// We temporarily redirect stderr to /dev/null to avoid spamming test output
	oldStderr := os.Stderr
	devNull, _ := os.Open(os.DevNull)
	os.Stderr = devNull
	defer func() {
		os.Stderr = oldStderr
		devNull.Close()
	}()

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()
			l.Info("Info message %d", id)
			l.V("Verbose message %d", id)
			l.VV("Very verbose message %d", id)
			l.Error("Error message %d", id)
			l.Section(fmt.Sprintf("Section %d", id))
			l.Detail("Detail %d", id)
		}(i)
	}

	wg.Wait()
}

func TestLogger_Levels(t *testing.T) {
	tests := []struct {
		name     string
		level    int
		logFunc  func(*Logger)
		expected string
	}{
		{
			name:  "Info always shows",
			level: 0,
			logFunc: func(l *Logger) {
				l.Info("test info")
			},
			expected: "[+] test info\n",
		},
		{
			name:  "Error always shows",
			level: 0,
			logFunc: func(l *Logger) {
				l.Error("test error")
			},
			expected: "[!] test error\n",
		},
		{
			name:  "Verbose shows at level 1",
			level: 1,
			logFunc: func(l *Logger) {
				l.V("test verbose")
			},
			expected: "[*] test verbose\n",
		},
		{
			name:  "Verbose hidden at level 0",
			level: 0,
			logFunc: func(l *Logger) {
				l.V("test verbose")
			},
			expected: "",
		},
		{
			name:  "VeryVerbose shows at level 2",
			level: 2,
			logFunc: func(l *Logger) {
				l.VV("test very verbose")
			},
			expected: "[VV] test very verbose\n",
		},
		{
			name:  "VeryVerbose hidden at level 1",
			level: 1,
			logFunc: func(l *Logger) {
				l.VV("test very verbose")
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLogger(tt.level)
			output := captureStderr(func() {
				tt.logFunc(l)
			})
			if output != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestLogger_Formatting(t *testing.T) {
	l := NewLogger(1)
	output := captureStderr(func() {
		l.Info("Hello %s", "World")
	})
	if !strings.Contains(output, "Hello World") {
		t.Errorf("expected output to contain 'Hello World', got %q", output)
	}
}
