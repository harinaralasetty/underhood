package cli

import (
	"bytes"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidTargets(t *testing.T) {
	dir := testutil.TempDir(t)
	bad := filepath.Join(dir, "Bad.app")
	if e := os.MkdirAll(filepath.Join(bad, "Contents", "Info.plist"), 0755); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{filepath.Join(dir, "missing.app"), dir, bad} {
		var out, err bytes.Buffer
		if got := Run([]string{p}, &out, &err); got != 2 {
			t.Fatalf("%s: %d %s", p, got, err.String())
		}
	}
}
func TestCLIAndOutputProtection(t *testing.T) {
	root := testutil.App(t, false)
	outpath := filepath.Join(testutil.TempDir(t), "report")
	var out, err bytes.Buffer
	if code := Run([]string{root, "--format", "both", "--output", outpath}, &out, &err); code != 0 {
		t.Fatal(code, err.String())
	}
	for _, s := range []string{".md", ".json"} {
		if _, e := os.Stat(outpath + s); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range []string{filepath.Join(root, "new.md"), filepath.Join(root, "Contents", "Info.plist"), outpath + ".md"} {
		if code := Run([]string{root, "--output", p}, &out, &err); code != 1 {
			t.Fatal("unsafe output", p, code)
		}
	}
	link := filepath.Join(testutil.TempDir(t), "hardlink")
	if e := os.Link(filepath.Join(root, "Contents", "Info.plist"), link); e == nil {
		if code := Run([]string{root, "--output", link}, &out, &err); code != 1 {
			t.Fatal("overwrote hardlink")
		}
	}
}
func TestArguments(t *testing.T) {
	for _, a := range [][]string{{}, {"x", "--format", "wat"}, {"x", "--format", "both"}, {"x", "--max-binary-mb", "0"}, {"x", "--max-binary-mb", "9223372036854775807"}, {"x", "--output"}, {"x", "--full", "--full"}} {
		if _, e := Parse(a); e == nil {
			t.Fatal(a)
		}
	}
	o, e := Parse([]string{"--full", "x.app", "--format", "json"})
	if e != nil || !o.Full || o.Format != "json" {
		t.Fatal(o, e)
	}
}

func TestCaseAliasOutput(t *testing.T) {
	root := testutil.App(t, false)
	alias := filepath.Join(filepath.Dir(root), "fixture.app")
	a, e := os.Stat(alias)
	if e != nil {
		t.Skip("case-sensitive filesystem")
	}
	b, e := os.Stat(root)
	if e != nil || !os.SameFile(a, b) {
		t.Skip("not an alias")
	}
	var out, err bytes.Buffer
	if code := Run([]string{root, "--output", filepath.Join(alias, "new.md")}, &out, &err); code != 1 {
		t.Fatal("allowed case alias inside target", code)
	}
}
