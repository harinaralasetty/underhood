package report

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/harinaralasetty/underhood/internal/model"
)

func baseID(id string) string { return strings.SplitN(id, "@", 2)[0] }

const summaryLimit = 8

var summaryLabels = map[string]string{
	"windows.pe.unsigned":   "Not signed",
	"windows.msix.unsigned": "Package not signed",

	"automation.NSAppleScriptEnabled":   "Declares AppleScript support",
	"automation.OSAScriptingDefinition": "Declares an AppleScript scripting dictionary",
	"automation.INIntentsSupported":     "Declares supported Siri intents",
	"automation.NSUserActivityTypes":    "Declares user activity types",
	"launch.SMPrivilegedExecutables":    "Declares privileged helper authorization",
	"launch.SMAuthorizedClients":        "Declares authorized helper clients",
}

type summaryGroup struct {
	key, category, text string
	severity            model.Severity
	ids, places, names  map[string]bool
	main                bool
}

// Summary retains every contributing ID while selecting up to eight diverse,
// severity-ranked declarations. Identity and ordinary signature metadata add no
// useful behavioural summary.
func Summary(findings []model.Finding) []model.SummaryItem {
	groups := map[string]*summaryGroup{}
	hasMSIX := false
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "windows.msix.") {
			hasMSIX = true
			break
		}
	}
	ordered := append([]model.Finding(nil), findings...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, f := range ordered {
		base := baseID(f.ID)
		if f.Category == "identity" || strings.HasPrefix(base, "bundle.") {
			continue
		}
		if strings.HasPrefix(base, "sign.") && f.Severity == model.Info && base != "sign.unsigned" && base != "sign.adhoc" {
			continue
		}
		if strings.HasPrefix(base, "windows.") && f.Severity == model.Info && (f.Category == "hardening" || f.Category == "sections" || base == "windows.imports.libraries") {
			continue
		}
		if strings.HasPrefix(base, "windows.msix.") && f.Severity == model.Info && f.Category == "signing" {
			continue
		}
		text := f.Title
		if strings.HasPrefix(base, "windows.pe.") && f.Severity == model.Info {
			continue
		}
		if strings.HasPrefix(base, "windows.manifest.") && len(f.Evidence) > 0 {
			value := f.Evidence[0].Value
			weight := func(v string) int {
				switch v {
				case "requireAdministrator":
					return 3
				case "highestAvailable":
					return 2
				case "true":
					return 1
				}
				return 0
			}
			for _, ev := range f.Evidence {
				if weight(ev.Value) > weight(value) {
					value = ev.Value
				}
			}
			switch base {
			case "windows.manifest.requestedExecutionLevel":
				switch value {
				case "requireAdministrator":
					text = "Requires administrator privileges"
				case "highestAvailable":
					text = "Requests highest available privileges"
				case "asInvoker":
					text = "Runs with the invoking user's privileges"
				}
			case "windows.manifest.uiAccess":
				if strings.EqualFold(value, "true") {
					text = "Requests access to higher-privilege user interfaces"
				} else {
					text = "Does not request elevated UI access"
				}
			case "windows.manifest.autoElevate":
				if strings.EqualFold(value, "true") {
					text = "Declares automatic elevation"
				} else {
					text = "Automatic elevation disabled"
				}
			}
		}

		if label, ok := summaryLabels[base]; ok {
			text = label
		}
		if hasMSIX && base == "windows.pe.unsigned" && strings.Contains(f.ID, "@") {
			text = "Embedded executable not signed"
		}
		if strings.HasPrefix(base, "registration.CFBundleDocumentTypes.") {
			text = "Declares supported document types"
		}
		if strings.HasPrefix(base, "registration.UTImportedTypeDeclarations.") {
			text = "Declares imported document types"
		}
		if strings.HasPrefix(base, "registration.UTExportedTypeDeclarations.") {
			text = "Declares exported document types"
		}
		if strings.HasPrefix(base, "registration.NSServices.") {
			text = "Declares system Services menu entries"
		}
		if strings.HasPrefix(base, "ent.") && base != "ent.no-sandbox" {
			detail := strings.TrimPrefix(f.Detail, "Disabled declaration: ")
			text = strings.SplitN(detail, ": ", 2)[0]
			if text == "Unmapped entitlement (raw declaration)" || text == "" {
				continue
			}
			if strings.HasPrefix(f.Detail, "Disabled declaration: ") {
				text = "Disabled declaration: " + text
			}
		}
		key := base
		if strings.HasPrefix(base, "windows.manifest.") {
			key += "=" + text
		}
		switch {
		case strings.HasPrefix(base, "windows.msix.restricted."):
			key = "windows.msix.restricted"
		case strings.HasPrefix(base, "windows.msix.capability."):
			key = "windows.msix.capability"
		case strings.HasPrefix(base, "privacy."):
			key = "privacy"
		case strings.HasPrefix(base, "url.scheme."):
			key = "url.scheme"
		case strings.HasPrefix(base, "net.host."):
			key = "net.host"
		case strings.HasPrefix(base, "automation.") && strings.TrimPrefix(base, "automation.") != "NSAppleScriptEnabled" && (strings.HasSuffix(base, ".intent") || strings.HasSuffix(base, ".action") || strings.HasSuffix(base, ".title") || strings.HasSuffix(base, ".appintents")):
			key = "appintents"
		case strings.HasPrefix(base, "ent.com.apple.security.temporary-exception."):
			key = "temporary-exception"
		}
		g := groups[key]
		if g == nil {
			g = &summaryGroup{key: key, category: f.Category, text: text, severity: f.Severity, ids: map[string]bool{}, places: map[string]bool{}, names: map[string]bool{}}
			groups[key] = g
		}
		g.ids[f.ID] = true
		place := strings.TrimPrefix(f.ID, base)
		if place == "" {
			g.main = true
		}
		g.places[place] = true
		if rank(f.Severity) > rank(g.severity) {
			g.severity = f.Severity
		}
		switch key {
		case "windows.msix.restricted":
			g.names[strings.TrimPrefix(base, "windows.msix.restricted.")] = true
		case "windows.msix.capability":
			g.names[strings.TrimPrefix(base, "windows.msix.capability.")] = true
		case "privacy":
			g.names[privacyName(strings.TrimPrefix(base, "privacy."))] = true
		case "url.scheme":
			g.names[strings.TrimPrefix(base, "url.scheme.")] = true
		case "net.host":
			g.names[strings.TrimPrefix(base, "net.host.")] = true
		case "temporary-exception":
			g.names[strings.TrimPrefix(base, "ent.com.apple.security.temporary-exception.")] = true
		}
	}
	all := []*summaryGroup{}
	for _, g := range groups {
		all = append(all, g)
	}
	less := func(a, b *summaryGroup) bool {
		if rank(a.severity) != rank(b.severity) {
			return rank(a.severity) > rank(b.severity)
		}
		return a.key < b.key
	}
	sort.Slice(all, func(i, j int) bool { return less(all[i], all[j]) })
	selected := []*summaryGroup{}
	used, cats := map[string]bool{}, map[string]bool{}
	add := func(g *summaryGroup) { selected = append(selected, g); used[g.key] = true; cats[g.category] = true }
	for _, g := range all {
		if len(selected) < summaryLimit && !cats[g.category] {
			add(g)
		}
	}
	for _, g := range all {
		if len(selected) < summaryLimit && !used[g.key] {
			add(g)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return less(selected[i], selected[j]) })
	out := []model.SummaryItem{}
	seen := map[string]int{}
	for _, g := range selected {
		text, ids := g.description(), sortedKeys(g.ids)
		if i, ok := seen[text]; ok { // e.g. entitlement and network views of the same declaration
			out[i].FindingIDs = append(out[i].FindingIDs, ids...)
			sort.Strings(out[i].FindingIDs)
			continue
		}
		seen[text] = len(out)
		out = append(out, model.SummaryItem{Text: text, FindingIDs: ids})
	}
	if len(out) == 0 {
		out = append(out, model.SummaryItem{Text: "No notable declarations found in the scanned files.", FindingIDs: []string{}})
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func namesList(m map[string]bool, limit int) string {
	names := sortedKeys(m)
	if len(names) > limit {
		return strings.Join(names[:limit], ", ") + ", …"
	}
	return strings.Join(names, ", ")
}
func (g *summaryGroup) description() string {
	n := len(g.places)
	switch g.key {
	case "windows.msix.restricted":
		return fmt.Sprintf("Declares %d restricted capabilities: %s", len(g.names), namesList(g.names, 4))
	case "windows.msix.capability":
		return fmt.Sprintf("Declares %d capabilities: %s", len(g.names), namesList(g.names, 4))
	case "net.sdk.sparkle":
		g.text = "Possible embedded self-updater: Sparkle"
	case "sign.unsigned":
		g.text = "Not signed"
	case "sign.adhoc":
		g.text = "Ad-hoc signed"
	case "ent.com.apple.security.app-sandbox":
		return "App Sandbox enabled"
	case "ent.no-sandbox":
		if g.main {
			if n == 1 {
				return "App Sandbox not enabled in main app"
			}
			return fmt.Sprintf("App Sandbox not enabled in main app and %d nested helpers", n-1)
		}
		return fmt.Sprintf("App Sandbox not enabled in %d nested helpers", n)
	case "appintents":
		return fmt.Sprintf("Declares App Intents / Shortcuts actions (%d metadata entries)", len(g.ids))
	case "temporary-exception":
		return fmt.Sprintf("Requests %d sandbox temporary exceptions: %s", len(g.names), namesList(g.names, 3))
	case "privacy":
		return fmt.Sprintf("Declares %d privacy permissions: %s", len(g.names), namesList(g.names, 4))
	case "url.scheme":
		return fmt.Sprintf("Registers %d URL schemes: %s", len(g.names), namesList(g.names, 3))
	case "launch.embedded":
		return fmt.Sprintf("Ships %d launch helpers", n)
	case "launch.plist":
		return fmt.Sprintf("Declares %d launch agents/daemons", n)
	case "net.host":
		return fmt.Sprintf("%d distinct hosts found as strings in binaries; strings are not proof of traffic", len(g.names))
	}
	if n > 1 {
		return fmt.Sprintf("%s (%d distinct bundles/places)", g.text, n)
	}
	return g.text
}
func privacyName(key string) string {
	key = strings.TrimPrefix(key, "NS")
	key = strings.ReplaceAll(key, "UsageDescription", "")
	var b strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// summaryLine prints readable text only; the full ID trail stays in JSON.
func summaryLine(s model.SummaryItem) string { return "- " + escape(s.Text) + "\n" }
