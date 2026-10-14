// Package model defines the portable schema shared by target implementations.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Version is the development tool version.
const Version = "0.1.0-dev"

// Resource bounds apply to every target.
const (
	MaxFiles        = 20000
	MaxDepth        = 4
	MaxMetadata     = 16 << 20
	DefaultBinaryMB = 300
	MaxHosts        = 200
	MaxHostEvidence = 20
)

// Severity describes a declaration's sensitivity, not a safety verdict.
type Severity string

const (
	Info      Severity = "info"
	Notable   Severity = "notable"
	Sensitive Severity = "sensitive"
)

// Confidence identifies the evidence source.
type Confidence string

const (
	Declared  Confidence = "declared"
	Binary    Confidence = "found-in-binary"
	Heuristic Confidence = "heuristic"
)

// Categories is the stable presentation order.
var Categories = []string{"identity", "signing", "entitlements", "permissions", "registrations", "launchItems", "automation", "network", "windows-manifest", "capabilities", "imports", "hardening", "sections"}

// Evidence locates a declaration or byte string.
type Evidence struct {
	File    string `json:"file"`
	Locator string `json:"locator"`
	Value   string `json:"value"`
}

// Finding is a stable, evidence-backed claim.
type Finding struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}

// SkipNote records unavailable data, failures, or exhausted bounds.
type SkipNote struct {
	Analyzer string `json:"analyzer"`
	File     string `json:"file"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
}

// Target identifies the inspected artifact.
type Target struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version string `json:"version"`
	Build   string `json:"build"`
}

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SummaryItem groups related findings and cites every contributing ID.
type SummaryItem struct {
	Text       string   `json:"text"`
	FindingIDs []string `json:"findingIDs"`
}

// Report is schema version 2.
type Report struct {
	SchemaVersion int           `json:"schemaVersion"`
	Tool          Tool          `json:"tool"`
	ScannedAt     string        `json:"scannedAt"`
	Target        Target        `json:"target"`
	Summary       []SummaryItem `json:"summary"`
	Findings      []Finding     `json:"findings"`
	Skipped       []SkipNote    `json:"skipped"`
	Limits        []string      `json:"limits"`
}

// Options controls bounded binary scanning.
type Options struct {
	MaxBinaryMB   int64
	BinaryStrings bool
}

// Text renders plist values deterministically.
func Text(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, e := json.Marshal(v)
	if e != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// Enabled implements plist boolean/numeric truth.
func Enabled(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case uint64:
		return x != 0
	case float64:
		return x != 0
	case json.Number:
		return x != "0"
	}
	return false
}

// Clean replaces private absolute prefixes and bounds evidence by Unicode characters.
func Clean(s, root, home string) string {
	if root != "" {
		s = strings.ReplaceAll(s, root, ".")
	}
	if home != "" {
		s = strings.ReplaceAll(s, home, "~")
	}
	return s
}

// Truncate bounds a display value without splitting UTF-8.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
