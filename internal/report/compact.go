package report

import (
	"fmt"
	"github.com/harinaralasetty/underhood/internal/model"
	"io"
	"sort"
	"strings"
)

// compact uses reusable path and locator labels while retaining one block per finding.
func compact(w io.Writer, r model.Report) error {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	paths, locators := map[string]string{}, map[string]string{}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "net.host.") {
			continue
		}
		for _, e := range f.Evidence[:1] {
			paths[e.File] = ""
			locators[e.Locator] = ""
		}
		if i := strings.IndexByte(f.ID, '@'); i >= 0 {
			paths[f.ID[i+1:]] = ""
		}
	}
	assign := func(m map[string]string, prefix string) []string {
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			m[k] = fmt.Sprintf("%s%d", prefix, i+1)
		}
		return keys
	}
	pathKeys := assign(paths, "P")
	locKeys := assign(locators, "L")
	id := func(s string) string {
		if i := strings.IndexByte(s, '@'); i >= 0 {
			if ref, ok := paths[s[i+1:]]; ok {
				return s[:i+1] + ref
			}
		}
		return s
	}
	p("# Underhood: %s\n\n**ID:** %s  \n**Version / build:** %s / %s  \n**Path:** %s  \n**Tool version:** %s  \n**Scanned at:** %s\n\n## Summary\n\n", escape(r.Target.Name), escape(r.Target.ID), escape(r.Target.Version), escape(r.Target.Build), escape(r.Target.Path), r.Tool.Version, r.ScannedAt)
	for _, s := range r.Summary {
		ids := []string{}
		for _, v := range s.FindingIDs {
			ids = append(ids, id(v))
		}
		p("- %s [%s]\n", escape(s.Text), escape(strings.Join(ids, ", ")))
	}
	p("\nCompact view: each block starts with its finding ID. P/L references expand to exact paths/locators below; @P expands the ID suffix. One evidence entry per finding; --full or JSON includes all entries and full descriptions. I = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic.\n")
	for _, cat := range model.Categories {
		p("\n## %s\n\n", cat)
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
			sev := map[model.Severity]string{model.Info: "I", model.Notable: "N", model.Sensitive: "S"}[f.Severity]
			conf := map[model.Confidence]string{model.Declared: "D", model.Binary: "B", model.Heuristic: "H"}[f.Confidence]
			p("**%s** [%s/%s]", escape(id(f.ID)), sev, conf)
			if len(f.Evidence) > 1 {
				p(" (+%d evidence)", len(f.Evidence)-1)
			}
			p("  \n")
			e := f.Evidence[0]
			p("%s/%s = %s\n", paths[e.File], locators[e.Locator], escape(e.Value))
			// Keep explanations that add meaning beyond the raw identifier and value.
			if f.Category == "entitlements" && !strings.HasPrefix(f.ID, "ent.no-sandbox") {
				detail := strings.SplitN(f.Detail, ": ", 2)[0]
				if detail != "Unmapped entitlement (raw declaration)" {
					p("%s\n", escape(detail))
				}
			}
			p("\n")
		}
		if !found {
			p("none found\n")
		}
		if len(endpoints) > 0 {
			p("URL string present in a binary, not verified traffic. Counts reflect retained distinct URL evidence (caps may apply). Finding ID = net.host.<host>.\n\n| Host | #URLs | Example |\n| --- | ---: | --- |\n")
			for _, f := range endpoints {
				urls := map[string]bool{}
				for _, e := range f.Evidence {
					urls[e.Value] = true
				}
				p("| %s | %d | %s |\n", escape(strings.TrimPrefix(f.ID, "net.host.")), len(urls), escape(f.Evidence[0].Value))
			}
		}
	}
	p("\n## Evidence reference key\n\n")
	for _, k := range pathKeys {
		p("- %s: %s\n", paths[k], escape(k))
	}
	for _, k := range locKeys {
		p("- %s: %s\n", locators[k], escape(k))
	}
	p("\n## Skipped analyses and bounded scans\n\n")
	if len(r.Skipped) == 0 {
		p("None.\n")
	}
	for _, n := range r.Skipped {
		p("- %s · %s: %s", escape(n.Analyzer), escape(n.File), escape(n.Reason))
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
