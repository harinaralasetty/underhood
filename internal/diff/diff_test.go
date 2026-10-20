package diff

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/report"
	"github.com/harinaralasetty/underhood/internal/target"
)

func finding(id, category, value string, severity model.Severity) model.Finding {
	return model.Finding{ID: id, Category: category, Title: id, Detail: value, Severity: severity, Confidence: model.Declared,
		Evidence: []model.Evidence{{File: "Contents/Info.plist", Locator: id, Value: value}}}
}

func normalized(findings ...model.Finding) model.Report {
	return report.Build(target.Result{Target: model.Target{Kind: "macos-app", ID: "org.test.fixture"}, Findings: findings})
}

func TestCompare(t *testing.T) {
	a := finding("added", "permissions", "new", model.Sensitive)
	r := finding("removed", "registrations", "old", model.Notable)
	c := finding("changed", "entitlements", "old", model.Sensitive)
	n := finding("changed", "entitlements", "new", model.Info)
	u := finding("unchanged", "identity", "same", model.Info)
	old, new := normalized(c, r, u), normalized(u, n, a)
	got := Compare(old, new)
	want := []Change{{"changed", "entitlements", "changed", model.Sensitive, &c, &n}, {"added", "permissions", "added", model.Sensitive, nil, &a}, {"removed", "registrations", "removed", model.Notable, &r, nil}}
	if !reflect.DeepEqual(got.Changes, want) {
		t.Fatalf("changes: %#v", got.Changes)
	}
	if !strings.Contains(got.Summary[0].Text, "adds 1 finding, removes 1 finding and changes 1 finding") || !reflect.DeepEqual(got.Summary[0].FindingIDs, []string{"added", "changed", "removed"}) {
		t.Fatal(got.Summary)
	}
	if len(Compare(old, old).Changes) != 0 {
		t.Fatal("unchanged report differs")
	}
}

func TestChangedFieldsAndLocatorNoise(t *testing.T) {
	base := finding("same", "network", "value", model.Notable)
	for _, field := range []string{"category", "title", "detail", "severity", "confidence", "file", "locator", "value"} {
		t.Run(field, func(t *testing.T) {
			n := base
			n.Evidence = append([]model.Evidence{}, base.Evidence...)
			switch field {
			case "category":
				n.Category = "permissions"
			case "title":
				n.Title = "new title"
			case "detail":
				n.Detail = "new detail"
			case "severity":
				n.Severity = model.Sensitive
			case "confidence":
				n.Confidence = model.Binary
			case "file":
				n.Evidence[0].File = "other"
			case "locator":
				n.Evidence[0].Locator = "other declaration key"
			case "value":
				n.Evidence[0].Value = "new value"
			}
			if got := Compare(normalized(base), normalized(n)); len(got.Changes) != 1 || got.Changes[0].Status != "changed" {
				t.Fatal(got.Changes)
			}
		})
	}
	base.ID = "net.host.api.test"
	n := base
	n.Evidence = []model.Evidence{{File: base.Evidence[0].File, Value: "value", Locator: "byte 200"}, {File: base.Evidence[0].File, Value: "value", Locator: "byte 100"}}
	if got := Compare(normalized(base), normalized(n)); len(got.Changes) != 0 {
		t.Fatal("offsets and repeated occurrences should not change declarations", got.Changes)
	}
	old := normalized(base)
	new := normalized(base)
	new.Target.Path, new.Target.Name, new.ScannedAt = "copy.app", "copy", "different time"
	if len(Compare(old, new).Changes) != 0 {
		t.Fatal("report metadata became a finding")
	}
}

func TestSliceOffsetsAndDeclarationBindings(t *testing.T) {
	old := finding("sign.team", "signing", "merged signing metadata", model.Info)
	old.Evidence = []model.Evidence{
		{File: "binary", Locator: "Mach-O arm64 slice at byte 0/CodeDirectory/teamID", Value: "TEAMA"},
		{File: "binary", Locator: "Mach-O x86_64 slice at byte 4096/CodeDirectory/teamID", Value: "TEAMB"},
	}
	new := old
	new.Evidence = append([]model.Evidence{}, old.Evidence...)
	new.Evidence[0].Locator = "Mach-O arm64 slice at byte 16384/CodeDirectory/teamID"
	new.Evidence[1].Locator = "Mach-O x86_64 slice at byte 32768/CodeDirectory/teamID"
	if got := Compare(normalized(old), normalized(new)); len(got.Changes) != 0 {
		t.Fatal("slice positions became changes", got.Changes)
	}
	new.Evidence[0].Value, new.Evidence[1].Value = new.Evidence[1].Value, new.Evidence[0].Value
	if got := Compare(normalized(old), normalized(new)); len(got.Changes) != 1 {
		t.Fatal("lost architecture/value bindings", got.Changes)
	}
}

func TestOrderingAndDeterminism(t *testing.T) {
	fs := []model.Finding{finding("z", "network", "z", model.Info), finding("a", "network", "a", model.Notable), finding("s", "network", "s", model.Sensitive), finding("b", "network", "b", model.Notable), finding("i", "identity", "i", model.Info)}
	first := Compare(normalized(), normalized(fs...))
	ids := []string{}
	for _, c := range first.Changes {
		ids = append(ids, c.ID)
	}
	if !reflect.DeepEqual(ids, []string{"i", "s", "a", "b", "z"}) {
		t.Fatal(ids)
	}
	for i := 0; i < 20; i++ {
		fs = append(fs[1:], fs[0])
		got := Compare(normalized(), normalized(fs...))
		got.ScannedAt = first.ScannedAt
		for _, render := range []func(*bytes.Buffer, Report) error{
			func(b *bytes.Buffer, r Report) error { return JSON(b, r) },
			func(b *bytes.Buffer, r Report) error { return Markdown(b, r, false) },
			func(b *bytes.Buffer, r Report) error { return Markdown(b, r, true) },
		} {
			var a, b bytes.Buffer
			if err := render(&a, first); err != nil {
				t.Fatal(err)
			}
			if err := render(&b, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("nondeterministic output")
			}
		}
	}
}

func TestCoverageAndMismatches(t *testing.T) {
	for _, side := range []string{"OLD", "NEW"} {
		t.Run(side, func(t *testing.T) {
			old, new := normalized(), normalized(finding("net.host.api.test", "network", "https://api.test/", model.Notable))
			note := model.SkipNote{Analyzer: "Network", File: "Contents/MacOS/Fixture", Reason: "200-host cap reached", Count: 1}
			if side == "OLD" {
				old.Skipped = []model.SkipNote{note}
			} else {
				new.Skipped = []model.SkipNote{note}
			}
			got := Compare(old, new)
			if len(got.Changes) != 1 || len(got.Warnings) != 1 || !strings.Contains(got.Summary[0].Text, "1 new endpoint host") {
				t.Fatal(got)
			}
			var b bytes.Buffer
			if err := Markdown(&b, got, false); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), "200-host cap reached") || !strings.Contains(b.String(), "not proof of absence") {
				t.Fatal(b.String())
			}
			if side == "OLD" && !reflect.DeepEqual(got.Old.Skipped, old.Skipped) || side == "NEW" && !reflect.DeepEqual(got.New.Skipped, new.Skipped) {
				t.Fatal("lost notes")
			}
		})
	}
	old, new := normalized(), normalized()
	new.Target.Kind, new.Target.ID = "windows-pe", "Fixture.exe"
	got := Compare(old, new)
	if len(got.Warnings) != 2 || len(got.Changes) != 0 {
		t.Fatal(got)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRenderEvidenceAndErrors(t *testing.T) {
	f := finding("host", "network", "<script>\n*injected*", model.Notable)
	for i := 0; i < 5; i++ {
		f.Evidence = append(f.Evidence, model.Evidence{File: "binary", Locator: fmt.Sprintf("byte %d", i), Value: "url"})
	}
	r := Compare(normalized(), normalized(f))
	var compact, full bytes.Buffer
	if err := Markdown(&compact, r, false); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&full, r, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compact.String(), "<script>") || !strings.Contains(compact.String(), "more evidence entries") || strings.Contains(full.String(), "more evidence entries") {
		t.Fatal(compact.String(), full.String())
	}
	if err := JSON(failWriter{}, r); err == nil {
		t.Fatal("missing JSON write error")
	}
	if err := Markdown(failWriter{}, r, true); err == nil {
		t.Fatal("missing Markdown write error")
	}
}

func TestEscapeKeepsQuotesAndNeutralisesMarkup(t *testing.T) {
	got := escape(`Target IDs differ: OLD "a.b"; NEW "c#d" <x> & *y*`)
	want := `Target IDs differ: OLD "a.b"; NEW "c#d" &lt;x&gt; &amp; \*y\*`
	if got != want {
		t.Fatalf("escape() = %q, want %q", got, want)
	}
	if got := escape("# heading"); got != `\# heading` {
		t.Fatalf("leading # not escaped: %q", got)
	}
}
