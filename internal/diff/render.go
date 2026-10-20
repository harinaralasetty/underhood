package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
)

// JSON writes complete changes and both sides' coverage in deterministic order.
func JSON(w io.Writer, r Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var value any
	if err = json.Unmarshal(b, &value); err != nil {
		return err
	}
	e := json.NewEncoder(w)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

// escape neutralises Markdown and raw HTML in target-controlled text. Quotes are
// left as they are: escaping them as entities and then escaping '#' broke them.
func escape(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "`", "\\`", "|", "\\|", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]").Replace(s)
	if strings.HasPrefix(s, "#") {
		s = "\\" + s
	}
	return s
}

// Markdown groups every change by category and sensitivity. Compact mode only
// shortens detail/evidence; no changed finding or skip note is hidden.
func Markdown(w io.Writer, r Report, full bool) error {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p("# Underhood diff: %s → %s\n\n", escape(r.Old.Target.Name), escape(r.New.Target.Name))
	for _, s := range r.Summary {
		p("%s\n\n", escape(s.Text))
	}
	for _, warning := range r.Warnings {
		p("**Warning:** %s\n\n", escape(warning))
	}
	p("**OLD:** %s · %s · %s · version %s / build %s  \n", escape(r.Old.Target.Path), escape(r.Old.Target.Kind), escape(r.Old.Target.ID), escape(r.Old.Target.Version), escape(r.Old.Target.Build))
	p("**NEW:** %s · %s · %s · version %s / build %s  \n", escape(r.New.Target.Path), escape(r.New.Target.Kind), escape(r.New.Target.ID), escape(r.New.Target.Version), escape(r.New.Target.Build))
	p("**Tool version:** %s  \n**Scanned at:** %s\n\n", escape(r.Tool.Version), escape(r.ScannedAt))
	category := ""
	for _, c := range r.Changes {
		if category != c.Category {
			category = c.Category
			p("## %s\n\n", escape(category))
		}
		f := c.New
		if f == nil {
			f = c.Old
		}
		p("**%s · %s** · %s · %s\n\n", c.Status, escape(f.Title), c.Severity, escape(c.ID))
		for _, side := range []struct {
			label string
			f     *model.Finding
		}{{"OLD", c.Old}, {"NEW", c.New}} {
			if side.f == nil {
				continue
			}
			detail := side.f.Detail
			if !full {
				detail = model.Truncate(detail, 240)
			}
			p("%s (%s, %s): %s\n", side.label, side.f.Severity, side.f.Confidence, escape(detail))
			n := len(side.f.Evidence)
			if !full && n > 3 {
				n = 3
			}
			for _, e := range side.f.Evidence[:n] {
				p("- %s · %s · %s = %s\n", side.label, escape(e.File), escape(e.Locator), escape(e.Value))
			}
			if n < len(side.f.Evidence) {
				p("- %s: %d more evidence entries (use --full or JSON).\n", side.label, len(side.f.Evidence)-n)
			}
			p("\n")
		}
	}
	for _, side := range []struct {
		label string
		s     Snapshot
	}{{"OLD", r.Old}, {"NEW", r.New}} {
		p("## %s skipped analyses and bounded scans\n\n", side.label)
		if len(side.s.Skipped) == 0 {
			p("None.\n")
		}
		for _, note := range side.s.Skipped {
			p("- %s · %s — skipped: %s (×%d)\n", escape(note.Analyzer), escape(note.File), escape(note.Reason), note.Count)
		}
		p("\n## %s limits\n\n", side.label)
		for _, limit := range side.s.Limits {
			p("- %s\n", escape(limit))
		}
		p("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
