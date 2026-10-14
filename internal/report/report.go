// Package report normalizes schema v2 reports and renders deterministic output.
package report

import (
	"encoding/json"
	"fmt"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/target"
	"io"
	"sort"
	"strings"
	"time"
)

// Limits explains what every static report can and cannot establish.
var Limits = []string{
	"Static analysis only; the target app and its bundled binaries are never executed.",
	"Strings in a binary are not proof of network traffic; endpoints are not verified traffic.",
	"Runtime permission grants (TCC) are not visible.",
	"Runtime-built URLs and server-driven behaviour are invisible.",
	"App Intents and AppleScript detection is best-effort; none found does not mean none exist.",
	"Signatures are parsed, not cryptographically verified. Certificate names are unverified declarations.",
	"Gatekeeper and notarization status are not assessed.",
	"Apps may behave differently from what they declare.",
	"Symlinks are not traversed; nested bundles are limited to depth 4, inventory to 20,000 entries, and metadata to 16 MiB per file. Reached caps are reported.",
	"SDK names are heuristic evidence of inclusion, not proof of use. Findings are not a verdict of safety.",
}

func rank(s model.Severity) int {
	switch s {
	case model.Sensitive:
		return 2
	case model.Notable:
		return 1
	}
	return 0
}

// Build merges IDs and evidence, collapses repeated failures, and adds a diverse summary.
func Build(r target.Result) model.Report {
	f := append([]model.Finding{}, r.Findings...)
	sort.Slice(f, func(i, j int) bool {
		if f[i].ID != f[j].ID {
			return f[i].ID < f[j].ID
		}
		return f[i].Detail < f[j].Detail
	})
	merged := map[string]model.Finding{}
	for _, v := range f {
		if len(v.Evidence) == 0 {
			r.Skipped = append(r.Skipped, model.SkipNote{Analyzer: "Report", File: ".", Reason: "finding without evidence rejected: " + v.ID, Count: 1})
			continue
		}
		if old, ok := merged[v.ID]; ok {
			old.Evidence = append(old.Evidence, v.Evidence...)
			if rank(v.Severity) > rank(old.Severity) {
				old.Severity = v.Severity
				old.Detail = v.Detail
			}
			merged[v.ID] = old
		} else {
			merged[v.ID] = v
		}
	}
	f = []model.Finding{}
	for _, v := range merged {
		sort.Slice(v.Evidence, func(i, j int) bool {
			a, b := v.Evidence[i], v.Evidence[j]
			if a.File != b.File {
				return a.File < b.File
			}
			if a.Locator != b.Locator {
				return a.Locator < b.Locator
			}
			return a.Value < b.Value
		})
		ev := []model.Evidence{}
		for _, e := range v.Evidence {
			if len(ev) == 0 || ev[len(ev)-1] != e {
				ev = append(ev, e)
			}
		}
		v.Evidence = ev
		f = append(f, v)
	}
	sort.Slice(f, func(i, j int) bool {
		if f[i].Category != f[j].Category {
			return f[i].Category < f[j].Category
		}
		return f[i].ID < f[j].ID
	})
	notes := map[string]model.SkipNote{}
	for _, n := range r.Skipped {
		key := n.Analyzer + "\x00" + n.Reason
		if n.Count <= 0 {
			n.Count = 1
		}
		if old, ok := notes[key]; ok {
			old.Count += n.Count
			if old.File != n.File {
				old.File = "(multiple files)"
			}
			notes[key] = old
		} else {
			notes[key] = n
		}
	}
	skipped := []model.SkipNote{}
	for _, n := range notes {
		skipped = append(skipped, n)
	}
	sort.Slice(skipped, func(i, j int) bool {
		a, b := skipped[i], skipped[j]
		if a.Analyzer != b.Analyzer {
			return a.Analyzer < b.Analyzer
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.File < b.File
	})
	limits := append(append([]string{}, Limits...), r.Limits...)
	sort.Strings(limits)
	unique := []string{}
	for _, l := range limits {
		if len(unique) == 0 || unique[len(unique)-1] != l {
			unique = append(unique, l)
		}
	}
	return model.Report{SchemaVersion: 2, Tool: model.Tool{Name: "underhood", Version: model.Version}, ScannedAt: time.Now().UTC().Format(time.RFC3339Nano), Target: r.Target, Summary: Summary(f), Findings: f, Skipped: skipped, Limits: unique}
}

// Summary groups related nested declarations and chooses category variety before repeats.
func Summary(f []model.Finding) []model.SummaryItem {
	type group struct {
		category, title string
		severity        model.Severity
		ids             []string
	}
	groups := map[string]*group{}
	for _, v := range f {
		base := strings.SplitN(v.ID, "@", 2)[0]
		if strings.HasPrefix(base, "net.host.") {
			base = "net.host"
		}
		if base == "bundle.sandbox" {
			continue
		}
		key := v.Category + "\x00" + base
		g := groups[key]
		if g == nil {
			g = &group{category: v.Category, title: v.Title, severity: v.Severity}
			groups[key] = g
		}
		g.ids = append(g.ids, v.ID)
		if rank(v.Severity) > rank(g.severity) {
			g.severity = v.Severity
		}
		if base == "net.host" {
			g.title = "Endpoint string hosts"
		}
	}
	all := []*group{}
	for _, g := range groups {
		sort.Strings(g.ids)
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if rank(a.severity) != rank(b.severity) {
			return rank(a.severity) > rank(b.severity)
		}
		return a.ids[0] < b.ids[0]
	})
	out := []model.SummaryItem{}
	used := map[*group]bool{}
	categories := map[string]bool{}
	add := func(g *group) {
		text := g.title
		if len(g.ids) > 1 {
			text += fmt.Sprintf(" (%d findings)", len(g.ids))
			if strings.HasPrefix(g.ids[0], "ent.no-sandbox@") {
				text = fmt.Sprintf("App Sandbox not enabled in %d nested helpers", len(g.ids))
			}
		}
		out = append(out, model.SummaryItem{Text: text, FindingIDs: g.ids})
		used[g] = true
		categories[g.category] = true
	}
	for _, g := range all {
		if len(out) < 8 && !categories[g.category] {
			add(g)
		}
	}
	for _, g := range all {
		if len(out) < 8 && !used[g] {
			add(g)
		}
	}
	return out
}

// JSON writes indented JSON with sorted object keys and no HTML escaping.
func JSON(w io.Writer, r model.Report) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	var generic any
	if e = json.Unmarshal(b, &generic); e != nil {
		return e
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(generic)
}
func escape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.Join(strings.Fields(s), " ")
	if strings.HasPrefix(s, "#") {
		s = "\\" + s
	}
	return s
}

// Markdown writes a concise report, or every evidence item when full is true.
func Markdown(w io.Writer, r model.Report, full bool) error {
	if !full {
		return compact(w, r)
	}
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p("# Underhood: %s\n\n**ID:** %s  \n**Version / build:** %s / %s  \n**Path:** %s  \n**Tool version:** %s  \n**Scanned at:** %s\n\n## Summary\n\n", escape(r.Target.Name), escape(r.Target.ID), escape(r.Target.Version), escape(r.Target.Build), escape(r.Target.Path), r.Tool.Version, r.ScannedAt)
	for _, s := range r.Summary {
		p("- %s [%s]\n", escape(s.Text), escape(strings.Join(s.FindingIDs, ", ")))
	}
	titles := map[string]string{"identity": "Identity and bundle", "signing": "Signing and notarization", "entitlements": "Entitlements", "permissions": "Declared privacy permissions", "registrations": "URL schemes and document types", "launchItems": "Launch items, helpers and XPC services", "automation": "Automation surface", "network": "Network surface"}
	for _, cat := range model.Categories {
		p("\n## %s\n\n", titles[cat])
		found := false
		var endpoints []model.Finding
		for _, f := range r.Findings {
			if f.Category != cat {
				continue
			}
			found = true
			if strings.HasPrefix(f.ID, "net.host.") {
				endpoints = append(endpoints, f)
				continue
			}
			detail := f.Detail
			if !full {
				detail = model.Truncate(detail, 240)
			}
			p("**%s** · %s · %s · `%s`  \n%s\n", escape(f.Title), f.Severity, f.Confidence, escape(f.ID), escape(detail))
			n := len(f.Evidence)
			if !full && n > 3 {
				n = 3
			}
			for _, e := range f.Evidence[:n] {
				p("- %s · %s = %s\n", escape(e.File), escape(e.Locator), escape(e.Value))
			}
			if n < len(f.Evidence) {
				p("- … %d more evidence entries (use --full or JSON).\n", len(f.Evidence)-n)
			}
			p("\n")
		}
		if !found {
			p("none found\n")
		}
		if len(endpoints) > 0 {
			p("URL string present in a binary, not verified traffic. Counts are retained distinct URLs; caps may apply.\n\n| Host | #URLs | Example |\n| --- | ---: | --- |\n")
			for _, f := range endpoints {
				urls := map[string]bool{}
				for _, e := range f.Evidence {
					urls[e.Value] = true
				}
				p("| %s | %d | %s |\n", escape(strings.TrimPrefix(f.ID, "net.host.")), len(urls), escape(f.Evidence[0].Value))
				if full {
					for _, e := range f.Evidence {
						p("| ↳ %s | | %s · %s = %s |\n", escape(f.ID), escape(e.File), escape(e.Locator), escape(e.Value))
					}
				}
			}
		}
	}
	p("\n## Skipped analyses and bounded scans\n\n")
	if len(r.Skipped) == 0 {
		p("None.\n")
	}
	for _, n := range r.Skipped {
		p("- %s · %s — skipped: %s", escape(n.Analyzer), escape(n.File), escape(n.Reason))
		if n.Count > 1 {
			p(" (×%d)", n.Count)
		}
		p("\n")
	}
	p("\n## Limits of this scan\n\n")
	for _, l := range r.Limits {
		p("- %s\n", escape(l))
	}
	_, e := io.WriteString(w, b.String())
	return e
}
