package report

import (
	"github.com/harinaralasetty/underhood/internal/model"
	"strings"
)

// macOSOnly categories are omitted from Windows reports when they hold nothing.
var macOSOnly = map[string]bool{"entitlements": true, "permissions": true, "registrations": true, "launchItems": true, "automation": true}

func reportCategories(r model.Report) []string {
	var cats []string
	used := map[string]bool{}
	for _, f := range r.Findings {
		used[f.Category] = true
	}
	for _, cat := range model.Categories {
		if strings.HasPrefix(r.Target.Kind, "windows-") && macOSOnly[cat] && !used[cat] {
			continue
		}
		if !strings.HasPrefix(r.Target.Kind, "windows-") && (cat == "windows-manifest" || cat == "capabilities" || cat == "imports" || cat == "hardening" || cat == "sections") {
			continue
		}
		cats = append(cats, cat)
	}
	return cats
}
func categoryTitle(cat, fallback string) string {
	switch cat {
	case "windows-manifest":
		return "Windows application manifest"
	case "capabilities":
		return "Inferred capabilities"
	case "imports":
		return "Imported libraries and symbols"
	case "hardening":
		return "PE hardening declarations"
	case "sections":
		return "PE sections"
	}
	return fallback
}

// versionBuild keeps the macOS "version / build" form and drops an empty build on Windows targets.
func versionBuild(r model.Report) string {
	if strings.HasPrefix(r.Target.Kind, "windows-") && r.Target.Build == "" {
		return escape(r.Target.Version)
	}
	return escape(r.Target.Version) + " / " + escape(r.Target.Build)
}
