package logger

import (
	"fmt"
	"os"
	"sync"
)

// VerboseLevel represents the verbosity level for logging
type VerboseLevel int

const (
	// VerboseSilent means no verbose output
	VerboseSilent VerboseLevel = 0
	// VerboseNormal means standard verbose output (-v)
	VerboseNormal VerboseLevel = 1
	// VerboseVery means detailed debugging output (-vv)
	VerboseVery VerboseLevel = 2
)

// Logger handles verbose output at different levels
type Logger struct {
	level VerboseLevel
	mu    sync.Mutex
}

// NewLogger creates a new logger with the specified verbosity level
func NewLogger(level int) *Logger {
	return &Logger{level: VerboseLevel(level)}
}

// IsVerbose returns true if verbose mode is enabled (-v or -vv)
func (l *Logger) IsVerbose() bool {
	return l.level >= VerboseNormal
}

// IsVeryVerbose returns true if very verbose mode is enabled (-vv)
func (l *Logger) IsVeryVerbose() bool {
	return l.level >= VerboseVery
}

// V logs a message at verbose level (-v)
func (l *Logger) V(format string, args ...interface{}) {
	if l.IsVerbose() {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[*] "+format+"\n", args...)
	}
}

// VV logs a message at very verbose level (-vv)
func (l *Logger) VV(format string, args ...interface{}) {
	if l.IsVeryVerbose() {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[VV] "+format+"\n", args...)
	}
}

// Info logs an informational message (always shown unless silent)
func (l *Logger) Info(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[+] "+format+"\n", args...)
}

// Error logs an error message (always shown unless silent)
func (l *Logger) Error(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
}

// Section logs a section header for very verbose mode
func (l *Logger) Section(title string) {
	if l.IsVeryVerbose() {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Fprintf(os.Stderr, "\n[VV] === %s ===\n", title)
	}
}

// Detail logs a detail line for very verbose mode with indentation
func (l *Logger) Detail(format string, args ...interface{}) {
	if l.IsVeryVerbose() {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[VV] → "+format+"\n", args...)
	}
}
