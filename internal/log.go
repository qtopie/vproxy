package internal

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
	"sync"
	"syscall"
)

// Level represents log verbosity levels.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var (
	// currentLevel is the active minimum level to log.
	currentLevel = LevelInfo

	logger = stdlog.New(os.Stderr, "", stdlog.Lshortfile|stdlog.LstdFlags)

	dialerControl func(network, address string, c syscall.RawConn) error
	mu            sync.RWMutex
)

// SetDialerControl sets the global dialer control function.
func SetDialerControl(f func(network, address string, c syscall.RawConn) error) {
	mu.Lock()
	defer mu.Unlock()
	dialerControl = f
}

// GetDialerControl returns a function suitable for net.Dialer.Control.
func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	mu.RLock()
	f := dialerControl
	mu.RUnlock()
	return f
}

func levelString(l Level) string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

func shouldLog(l Level) bool {
	return l >= currentLevel
}

// SetLevel sets the active minimum log level.
func SetLevel(l Level) {
	currentLevel = l
}

// SetOutput sets the output destination for the logger.
func SetOutput(w io.Writer) {
	logger.SetOutput(w)
}

// SetVerbose is a convenience to enable debug level when true.
func SetVerbose(v bool) {
	if v {
		SetLevel(LevelDebug)
	} else {
		SetLevel(LevelInfo)
	}
}

// IsVerbose returns true if the current log level is Debug.
func IsVerbose() bool {
	return currentLevel == LevelDebug
}

// output logs the formatted message with given level if allowed. calldepth
// should be set by callers so file/line refer to the original caller.
func output(l Level, calldepth int, format string, v ...interface{}) {
	if !shouldLog(l) {
		return
	}
	prefix := fmt.Sprintf("[%s] ", levelString(l))
	msg := fmt.Sprintf(prefix+format, v...)
	// logger.Output expects calldepth; add 1 to account for this wrapper
	logger.Output(calldepth+1, msg)
	if l == LevelFatal {
		os.Exit(1)
	}
}

// Debugf prints debug-level logs.
func Debugf(format string, v ...interface{}) { output(LevelDebug, 2, format, v...) }

// Infof prints info-level logs.
func Infof(format string, v ...interface{}) { output(LevelInfo, 2, format, v...) }

// Warnf prints warning-level logs.
func Warnf(format string, v ...interface{}) { output(LevelWarn, 2, format, v...) }

// Errorf prints error-level logs.
func Errorf(format string, v ...interface{}) { output(LevelError, 2, format, v...) }

// Fatalf prints fatal-level logs and exits.
func Fatalf(format string, v ...interface{}) { output(LevelFatal, 2, format, v...) }

type logHelper struct {
	prefix string
}

func (l *logHelper) Write(p []byte) (n int, err error) {
	if shouldLog(LevelDebug) {
		// Use Debug level for helper writes
		output(LevelDebug, 2, "%s%s", l.prefix, string(p))
		return len(p), nil
	}
	return len(p), nil
}

func newLogHelper(prefix string) *logHelper { return &logHelper{prefix} }

// NewDebugWriter returns an io.Writer that writes log output with the given prefix
// only when debug/verbose mode is enabled. Useful to pass to other libraries.
func NewDebugWriter(prefix string) io.Writer { return newLogHelper(prefix) }

type stdLogBridge struct{}

func (stdLogBridge) Write(p []byte) (n int, err error) {
	// p usually ends with a newline; trim for nicer output
	s := string(p)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	// Route standard log output to INFO level (preserve call depth)
	output(LevelInfo, 3, "%s", s)
	return len(p), nil
}

func init() {
	// Default level respects existing Config.Verbose
	if shouldLog(LevelDebug) {
		SetLevel(LevelDebug)
	} else {
		SetLevel(LevelInfo)
	}
	// Redirect the standard library logger to our internal logger so all
	// existing `log.Printf`, `log.Println`, etc. go through `internal`.
	stdlog.SetFlags(0)
	stdlog.SetOutput(stdLogBridge{})
}
