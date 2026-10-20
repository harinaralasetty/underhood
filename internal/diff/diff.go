// Package diff compares normalized static reports without inspecting targets.
package diff

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/harinaralasetty/underhood/internal/model"
)

// Snapshot retains each side's identity and scan coverage, including every skip.
type Snapshot struct {
	Target  model.Target     `json:"target"`
	Skipped []model.SkipNote `json:"skipped"`
	Limits  []string         `json:"limits"`
}

// Change retains complete normalized findings on each available side. A nil side
// means not observed, not proof of absence when a scan was incomplete.
type Change struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Status   string         `json:"status"`
	Severity model.Severity `json:"severity"`
	Old      *model.Finding `json:"old"`
	New      *model.Finding `json:"new"`
}

// Report is the independently versioned diff schema; ordinary reports stay v2.
type Report struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Type          string              `json:"type"`
	Tool          model.Tool          `json:"tool"`
	ScannedAt     string              `json:"scannedAt"`
	Old           Snapshot            `json:"old"`
	New           Snapshot            `json:"new"`
	Warnings      []string            `json:"warnings"`
	Summary       []model.SummaryItem `json:"summary"`
	Changes       []Change            `json:"changes"`
}

func rank(s model.Severity) int {
	switch s {
	case model.Sensitive:
		return 2
	case model.Notable:
		return 1
	default:
		return 0
	}
}

type evidenceKey struct{ file, locator, value string }

// semanticLocator removes physical string/slice positions while preserving
// declaration keys and architecture associations within merged findings.
func semanticLocator(id, locator string) string {
	if strings.HasPrefix(id, "net.host.") || strings.HasPrefix(id, "windows.persistence.") {
		return ""
	}
	if strings.HasPrefix(locator, "Mach-O ") {
		prefix, rest, ok := strings.Cut(locator, " slice at byte ")
		if ok {
			n := 0
			for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
				n++
			}
			if n > 0 {
				return prefix + " slice" + rest[n:]
			}
		}
	}
	return locator
}

// semanticEvidence ignores physical positions and duplicate observations.
// Complete original locators remain in reported changes.
func semanticEvidence(f model.Finding, standalonePE bool) []evidenceKey {
	set := map[evidenceKey]bool{}
	for _, e := range f.Evidence {
		file := e.File
		if standalonePE {
			// The PE analyzer uses the input basename for the single root file.
			// Comparing old.exe with new.exe must not change every declaration.
			file = "."
		}
		set[evidenceKey{file, semanticLocator(f.ID, e.Locator), e.Value}] = true
	}
	keys := make([]evidenceKey, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.file != b.file {
			return a.file < b.file
		}
		if a.locator != b.locator {
			return a.locator < b.locator
		}
		return a.value < b.value
	})
	return keys
}

func equal(a, b model.Finding, oldStandalonePE, newStandalonePE bool) bool {
	return a.Category == b.Category && a.Title == b.Title && a.Detail == b.Detail &&
		a.Severity == b.Severity && a.Confidence == b.Confidence &&
		slices.Equal(semanticEvidence(a, oldStandalonePE), semanticEvidence(b, newStandalonePE))
}

// Compare matches the stable IDs of reports built by report.Build. It compares
// retained declarations only; it never guesses renames or unobserved values.
func Compare(old, new model.Report) Report {
	r := Report{SchemaVersion: 1, Type: "diff", Tool: model.Tool{Name: "underhood", Version: model.Version},
		ScannedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Old:       Snapshot{old.Target, append([]model.SkipNote{}, old.Skipped...), append([]string{}, old.Limits...)},
		New:       Snapshot{new.Target, append([]model.SkipNote{}, new.Skipped...), append([]string{}, new.Limits...)},
		Warnings:  []string{}, Summary: []model.SummaryItem{}, Changes: []Change{}}
	if old.Target.Kind != new.Target.Kind {
		r.Warnings = append(r.Warnings, fmt.Sprintf("Target kinds differ: OLD %q; NEW %q. Findings may not be comparable.", old.Target.Kind, new.Target.Kind))
	}
	if old.Target.ID != new.Target.ID {
		r.Warnings = append(r.Warnings, fmt.Sprintf("Target IDs differ: OLD %q; NEW %q. These may be different applications.", old.Target.ID, new.Target.ID))
	}
	if len(old.Skipped) > 0 || len(new.Skipped) > 0 {
		r.Warnings = append(r.Warnings, "Scan coverage is incomplete; inspect OLD and NEW skip notes. Added/removed means observed on one side only, not proof of absence on the other.")
	}
	byID := map[string]model.Finding{}
	for _, f := range old.Findings {
		byID[f.ID] = f
	}
	for _, f := range new.Findings {
		f := f
		previous, ok := byID[f.ID]
		delete(byID, f.ID)
		if !ok {
			r.Changes = append(r.Changes, Change{f.ID, f.Category, "added", f.Severity, nil, &f})
		} else if !equal(previous, f, old.Target.Kind == "windows-pe", new.Target.Kind == "windows-pe") {
			severity := f.Severity
			if rank(previous.Severity) > rank(severity) {
				severity = previous.Severity
			}
			r.Changes = append(r.Changes, Change{f.ID, f.Category, "changed", severity, &previous, &f})
		}
	}
	for _, f := range byID {
		f := f
		r.Changes = append(r.Changes, Change{f.ID, f.Category, "removed", f.Severity, &f, nil})
	}
	categories := map[string]int{}
	for i, cat := range model.Categories {
		categories[cat] = i + 1
	}
	sort.Slice(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		if categories[a.Category] != categories[b.Category] {
			return categories[a.Category] < categories[b.Category]
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
		}
		return a.ID < b.ID
	})
	ids := []string{}
	added, removed, changed, hosts, sensitive := 0, 0, 0, 0, 0
	for _, c := range r.Changes {
		ids = append(ids, c.ID)
		switch c.Status {
		case "added":
			added++
			if strings.HasPrefix(c.ID, "net.host.") {
				hosts++
			}
			if c.Severity == model.Sensitive && (c.Category == "entitlements" || c.Category == "permissions" || c.Category == "capabilities") {
				sensitive++
			}
		case "removed":
			removed++
		case "changed":
			changed++
		}
	}
	sort.Strings(ids)
	text := "No differences found in the retained static findings."
	if len(ids) > 0 {
		text = fmt.Sprintf("This update adds %s, removes %s and changes %s.", count(added, "finding"), count(removed, "finding"), count(changed, "finding"))
		additions := []string{}
		if sensitive > 0 {
			additions = append(additions, count(sensitive, "sensitive permission/entitlement/capability declaration"))
		}
		if hosts > 0 {
			additions = append(additions, count(hosts, "new endpoint host"))
		}
		if len(additions) > 0 {
			text += " Additions include " + strings.Join(additions, " and ") + "."
		}
	}
	r.Summary = append(r.Summary, model.SummaryItem{Text: text, FindingIDs: ids})
	return r
}

func count(n int, noun string) string {
	if n != 1 {
		noun += "s"
	}
	return fmt.Sprintf("%d %s", n, noun)
}
