package log

import (
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

var (
	helperMu   sync.RWMutex
	helperFunc = map[string]bool{}
)

// Helper marks the calling function as a log helper function.
// When logging file and line information, that function will be skipped.
// Helper may be called simultaneously from multiple goroutines.
func Helper() {
	name := callerName(1)
	if name == "" || isHelper(name) {
		return
	}
	markHelper(name)
}

func isHelper(name string) bool {
	helperMu.RLock()
	defer helperMu.RUnlock()
	return helperFunc[name]
}

func markHelper(name string) {
	helperMu.Lock()
	defer helperMu.Unlock()
	helperFunc[name] = true
}

func callerName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip + 1)
	if !ok {
		return ""
	}
	return runtime.FuncForPC(pc).Name()
}

// caller returns a string containing filename and line number of
// the nearest function invocation on the calling goroutine's stack,
// after skipping functions marked as helper functions.
// If no stack information is available, it returns "?:?".
func caller() string {
	for i := 1; ; i++ {
		// NOTE(kr): This is quadratic in the number of frames we
		// ultimately have to skip. Consider using Callers instead.
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			return "?:?"
		}
		if !isHelper(runtime.FuncForPC(pc).Name()) {
			return filepath.Base(file) + ":" + strconv.Itoa(line)
		}
	}
}
