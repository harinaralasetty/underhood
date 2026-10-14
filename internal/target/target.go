// Package target provides the small registry boundary for platform targets.
package target

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/harinaralasetty/underhood/internal/model"
)

// Context supplies a canonical input path and scan options.
type Context struct {
	Root    string
	Options model.Options
}

// Result contains target identity, findings, failures, and additional limits.
type Result struct {
	Target   model.Target
	Findings []model.Finding
	Skipped  []model.SkipNote
	Limits   []string
}

// Target is implemented by each independently registered target kind.
type Target interface {
	Kind() string
	Detect(path string) (bool, string)
	Analyze(Context) (Result, error)
}

var registry []Target
var mu sync.RWMutex

// Register adds a target kind at startup. Duplicate kinds are programming errors.
func Register(t Target) {
	mu.Lock()
	defer mu.Unlock()
	for _, old := range registry {
		if old.Kind() == t.Kind() {
			panic("duplicate target kind: " + t.Kind())
		}
	}
	registry = append(registry, t)
}

// Analyze detects a target and invokes it. Invalid inputs return an error.
func Analyze(path string, options model.Options) (Result, error) {
	root, e := filepath.Abs(path)
	if e != nil {
		return Result{}, e
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return Result{}, fmt.Errorf("resolve target path: %w", e)
	}
	mu.RLock()
	targets := append([]Target(nil), registry...)
	mu.RUnlock()
	sort.Slice(targets, func(i, j int) bool { return targets[i].Kind() < targets[j].Kind() })
	kinds := []string{}
	reasons := []string{}
	for _, t := range targets {
		kinds = append(kinds, t.Kind())
		ok, reason := t.Detect(root)
		if ok {
			return t.Analyze(Context{root, options})
		}
		if reason != "" {
			reasons = append(reasons, reason)
		}
	}
	return Result{}, fmt.Errorf("unrecognized or invalid target; supported kinds: %s (%s)", strings.Join(kinds, ", "), strings.Join(reasons, "; "))
}
