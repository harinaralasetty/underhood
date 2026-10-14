package report

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/harinaralasetty/underhood/internal/model"
)

func finding(id, cat string, sev model.Severity) model.Finding {
	return model.Finding{ID: id, Category: cat, Title: "Readable title", Detail: "Explanation: value", Severity: sev, Confidence: model.Declared, Evidence: []model.Evidence{{File: "Contents/test", Locator: "key", Value: "value"}}}
}
func TestSummaryRules(t *testing.T) {
	tests := []struct {
		name  string
		f     []model.Finding
		want  string
		count int
	}{
		{"empty", nil, "No notable declarations", 1},
		{"identity", []model.Finding{finding("bundle.CFBundleIdentifier", "identity", model.Info)}, "No notable declarations", 1},
		{"sign info", []model.Finding{finding("sign.authorities", "signing", model.Info)}, "No notable declarations", 1},
		{"unsigned", []model.Finding{finding("sign.unsigned", "signing", model.Notable)}, "Not signed", 1},
		{"adhoc", []model.Finding{finding("sign.adhoc", "signing", model.Notable)}, "Ad-hoc signed", 1},
		{"group", []model.Finding{finding("ent.no-sandbox", "entitlements", model.Sensitive), finding("ent.no-sandbox@a", "entitlements", model.Sensitive), finding("ent.no-sandbox@b", "entitlements", model.Sensitive)}, "main app and 2 nested helpers", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Summary(tt.f)
			if len(got) != tt.count || !strings.Contains(got[0].Text, tt.want) {
				t.Fatal(got)
			}
		})
	}
	var f []model.Finding
	for i := 0; i < 15; i++ {
		sev := []model.Severity{model.Info, model.Notable, model.Sensitive}[i%3]
		v := finding(fmt.Sprintf("family.%02d", i), []string{"automation", "network", "permissions"}[i%3], sev)
		v.Title = fmt.Sprintf("Title %02d", i)
		f = append(f, v)
	}
	s := Summary(f)
	if len(s) != 8 {
		t.Fatal(s)
	}
	severity := map[string]model.Severity{}
	for _, v := range f {
		severity[v.ID] = v.Severity
	}
	for i := 1; i < len(s); i++ {
		if rank(severity[s[i-1].FindingIDs[0]]) < rank(severity[s[i].FindingIDs[0]]) {
			t.Fatal("out of rank order", s)
		}
	}
	for i, j := 0, len(f)-1; i < j; i, j = i+1, j-1 {
		f[i], f[j] = f[j], f[i]
	}
	if !reflect.DeepEqual(s, Summary(f)) {
		t.Fatal("nondeterministic")
	}
}
func TestSummaryNamesAndEvidence(t *testing.T) {
	var f []model.Finding
	for _, name := range []string{"c", "a", "d", "b"} {
		f = append(f, finding("url.scheme."+name, "registrations", model.Notable))
	}
	s := Summary(f)
	if s[0].Text != "Registers 4 URL schemes: a, b, c, …" || len(s[0].FindingIDs) != 4 {
		t.Fatal(s)
	}
	for _, full := range []bool{false, true} {
		var b bytes.Buffer
		if e := Markdown(&b, model.Report{Summary: s}, full); e != nil {
			t.Fatal(e)
		}
		line := strings.Split(strings.Split(b.String(), "## Summary\n\n")[1], "\n")[0]
		if line != "- Registers 4 URL schemes: a, b, c, …" {
			t.Fatal(line)
		}
	}
}
func TestCompactQualityAndCaps(t *testing.T) {
	r := model.Report{}
	for i := 0; i < 30; i++ {
		r.Findings = append(r.Findings, finding(fmt.Sprintf("automation.intent@%02d", i), "automation", model.Info))
	}
	r.Findings = append(r.Findings, finding("automation.intent@zz-sensitive", "automation", model.Sensitive), finding("automation.intent@zz-notable", "automation", model.Notable), finding("bundle.CFBundleIdentifier@Contents/Helper.app", "identity", model.Info))
	var b bytes.Buffer
	if e := Markdown(&b, r, false); e != nil {
		t.Fatal(e)
	}
	s := b.String()
	for _, bad := range []string{"P1/", "L1", "Evidence reference key", "**CFBundleIdentifier@"} {
		if strings.Contains(s, bad) {
			t.Fatal(bad)
		}
	}
	for _, want := range []string{"Contents/test · key = value", "### Nested bundles", "| Path | Bundle ID | Version | Build | Sandbox |", "… and 21 more (use --full or JSON)", "automation.intent@zz-sensitive"} {
		if !strings.Contains(s, want) {
			t.Fatal("missing", want, s)
		}
	}
	if strings.Contains(s, "automation.intent@zz-notable") {
		t.Fatal("bulk notable family member should be capped in compact mode")
	}
	if n := strings.Count(s, "**Readable title**"); n != 11 {
		t.Fatal("wrong visible family count", n)
	}
}
func TestCompactEndpointsAndSkips(t *testing.T) {
	r := model.Report{}
	for i := 0; i < 60; i++ {
		r.Findings = append(r.Findings, finding(fmt.Sprintf("net.host.%02d.example", i), "network", model.Info))
	}
	f := finding("net.host.last.example", "network", model.Sensitive)
	f.Evidence = append(f.Evidence, model.Evidence{Value: "another"})
	r.Findings = append(r.Findings, f)
	for i := 0; i < 25; i++ {
		r.Skipped = append(r.Skipped, model.SkipNote{Analyzer: "test", Reason: fmt.Sprint(i), Count: 2})
	}
	var b bytes.Buffer
	Markdown(&b, r, false)
	s := b.String()
	if !strings.Contains(s, "… and 11 more") || !strings.Contains(s, "… and 5 more") || !strings.Contains(s, "| last.example | 2 |") {
		t.Fatal(s)
	}
	if strings.Index(s, "| last.example |") > strings.Index(s, "| 00.example |") {
		t.Fatal("host count sorting")
	}
}
