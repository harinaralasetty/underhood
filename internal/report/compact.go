package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
)

const compactFamilyLimit = 10
const compactEntitlementLimit = 3
const compactHostLimit = 50
const compactSkipLimit = 20

// compact presents inline evidence; only informational repetition is capped.
func compact(w io.Writer, r model.Report) error {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("# Underhood: %s\n\n**ID:** %s  \n**Version / build:** %s / %s  \n**Path:** %s  \n**Tool version:** %s  \n**Scanned at:** %s\n\n## Summary\n\n", escape(r.Target.Name), escape(r.Target.ID), escape(r.Target.Version), escape(r.Target.Build), escape(r.Target.Path), r.Tool.Version, r.ScannedAt)
	for _, s := range r.Summary {
		p("%s", summaryLine(s))
	}
	p("\nI = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic. Use --full or JSON for every evidence entry.\n")
	findings := append([]model.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	nested := nestedBundles(findings)
	for _, cat := range model.Categories {
		p("\n## %s\n\n", cat)
		found := false
		var endpoints []model.Finding
		counts, omitted, places := map[string]int{}, map[string]int{}, map[string][]string{}
		for _, f := range findings {
			if f.Category != cat {
				continue
			}
			found = true
			if cat == "identity" && strings.Contains(f.ID, "@") && f.Severity == model.Info {
				continue
			}
			if strings.HasPrefix(f.ID, "net.host.") {
				endpoints = append(endpoints, f)
				continue
			}
			base := baseID(f.ID)
			limit := 0
			switch {
			case f.Severity != model.Sensitive && cat == "entitlements":
				limit = compactEntitlementLimit
			case f.Severity == model.Info:
				limit = compactFamilyLimit
			case f.Severity == model.Notable && strings.HasPrefix(base, "automation.") && base != "automation.NSAppleScriptEnabled":
				limit = compactFamilyLimit
			}
			if limit > 0 {
				counts[base]++
				if counts[base] > limit {
					omitted[base]++
					if i := strings.IndexByte(f.ID, '@'); i >= 0 {
						places[base] = append(places[base], f.ID[i+1:])
					}
					continue
				}
			}
			sev := map[model.Severity]string{model.Info: "I", model.Notable: "N", model.Sensitive: "S"}[f.Severity]
			conf := map[model.Confidence]string{model.Declared: "D", model.Binary: "B", model.Heuristic: "H"}[f.Confidence]
			p("**%s** · %s/%s · `%s`  \n", escape(f.Title), sev, conf, escape(f.ID))
			if len(f.Evidence) > 0 {
				e := f.Evidence[0]
				p("%s · %s = %s\n", escape(e.File), escape(e.Locator), escape(e.Value))
			}
			if cat == "entitlements" || cat == "permissions" {
				detail := strings.SplitN(f.Detail, ": ", 2)[0]
				if detail != "Unmapped entitlement (raw declaration)" && detail != "" {
					p("%s\n", escape(detail))
				}
			}
			p("\n")
		}
		keys := []string{}
		for key := range omitted {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if ps := places[key]; len(ps) > 0 && cat == "entitlements" {
				if len(ps) > 4 {
					ps = append(ps[:4:4], "…")
				}
				p("%s: also declared in %d more places (%s); use --full or JSON for values\n\n", escape(key), omitted[key], escape(strings.Join(ps, ", ")))
				continue
			}
			p("%s: … and %d more (use --full or JSON)\n\n", escape(key), omitted[key])
		}
		if cat == "identity" && len(nested) > 0 {
			p("### Nested bundles\n\n| Path | Bundle ID | Version | Build | Sandbox |\n| --- | --- | --- | --- | --- |\n")
			paths := []string{}
			for path := range nested {
				paths = append(paths, path)
			}
			sort.Strings(paths)
			for _, path := range paths {
				v := nested[path]
				p("| %s | %s | %s | %s | %s |\n", escape(path), escape(v[0]), escape(v[1]), escape(v[2]), escape(v[3]))
			}
		}
		if !found {
			p("none found\n")
		}
		if len(endpoints) > 0 {
			urls := func(f model.Finding) int {
				m := map[string]bool{}
				for _, e := range f.Evidence {
					m[e.Value] = true
				}
				return len(m)
			}
			sort.Slice(endpoints, func(i, j int) bool {
				a, c := urls(endpoints[i]), urls(endpoints[j])
				if a != c {
					return a > c
				}
				return endpoints[i].ID < endpoints[j].ID
			})
			p("URL string present in a binary, not verified traffic. Counts reflect retained distinct URL evidence (caps may apply). Finding ID = net.host.<host>.\n\n| Host | #URLs | Example |\n| --- | ---: | --- |\n")
			omitted := 0
			for i, f := range endpoints {
				if i >= compactHostLimit && f.Severity == model.Info {
					omitted++
					continue
				}
				example := ""
				if len(f.Evidence) > 0 {
					example = f.Evidence[0].Value
				}
				p("| %s | %d | %s |\n", escape(strings.TrimPrefix(f.ID, "net.host.")), urls(f), escape(example))
			}
			if omitted > 0 {
				p("\n… and %d more (use --full or JSON)\n", omitted)
			}
		}
	}
	p("\n## Skipped analyses and bounded scans\n\n")
	if len(r.Skipped) == 0 {
		p("None.\n")
	}
	for i, n := range r.Skipped {
		if i == compactSkipLimit {
			p("… and %d more (use --full or JSON)\n", len(r.Skipped)-i)
			break
		}
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
	_, err := io.WriteString(w, b.String())
	return err
}

func nestedBundles(findings []model.Finding) map[string][4]string {
	rows := map[string][4]string{}
	for _, f := range findings {
		parts := strings.SplitN(f.ID, "@", 2)
		if len(parts) != 2 || f.Category != "identity" {
			continue
		}
		row := rows[parts[1]]
		if len(f.Evidence) > 0 {
			switch parts[0] {
			case "bundle.CFBundleIdentifier":
				row[0] = f.Evidence[0].Value
			case "bundle.CFBundleShortVersionString":
				row[1] = f.Evidence[0].Value
			case "bundle.CFBundleVersion":
				row[2] = f.Evidence[0].Value
			}
		}
		rows[parts[1]] = row
	}
	for _, f := range findings {
		parts := strings.SplitN(f.ID, "@", 2)
		if len(parts) != 2 {
			continue
		}
		row, ok := rows[parts[1]]
		if !ok {
			continue
		}
		if parts[0] == "ent.com.apple.security.app-sandbox" && len(f.Evidence) > 0 {
			row[3] = f.Evidence[0].Value
		}
		if parts[0] == "ent.no-sandbox" {
			row[3] = "not enabled"
		}
		rows[parts[1]] = row
	}
	return rows
}
