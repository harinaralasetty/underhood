package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	for _, p := range []string{filepath.Join(root, "new.md"), filepath.Join(root, "Contents", "Info.plist")} {
		if code := Run([]string{root, "--output", p}, &out, &err); code != 1 {
			t.Fatal("unsafe output", p, code)
		}
	}
	link := filepath.Join(testutil.TempDir(t), "hardlink")
	if e := os.Link(filepath.Join(root, "Contents", "Info.plist"), link); e == nil {
		before, _ := os.ReadFile(filepath.Join(root, "Contents", "Info.plist"))
		if code := Run([]string{root, "--output", link}, &out, &err); code != 0 {
			t.Fatal(code, err.String())
		}
		after, _ := os.ReadFile(filepath.Join(root, "Contents", "Info.plist"))
		report, _ := os.ReadFile(link)
		if !bytes.Equal(before, after) || !bytes.Contains(report, []byte("# Underhood")) {
			t.Fatal("hard-link replacement damaged target or omitted report")
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

func TestSymlinkTarget(t *testing.T) {
	root := testutil.App(t, false)
	link := filepath.Join(testutil.TempDir(t), "Link.app")
	if e := os.Symlink(root, link); e != nil {
		t.Skip(e)
	}
	var out, err bytes.Buffer
	if code := Run([]string{link, "--format", "json"}, &out, &err); code != 0 {
		t.Fatal(code, err.String())
	}
	var rep model.Report
	if e := json.Unmarshal(out.Bytes(), &rep); e != nil {
		t.Fatal(e)
	}
	resolved, e := filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	if rep.Target.Path != resolved {
		t.Fatalf("path %q != %q", rep.Target.Path, resolved)
	}
	if code := Run([]string{link, "--output", filepath.Join(root, "report.md")}, &out, &err); code != 1 {
		t.Fatal("allowed output inside resolved target", code)
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(root, "missing.app"), link); e != nil {
		t.Fatal(e)
	}
	if code := Run([]string{link}, &out, &err); code != 2 {
		t.Fatal("dangling symlink", code)
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Dir(root), link); e != nil {
		t.Fatal(e)
	}
	if code := Run([]string{link}, &out, &err); code != 2 {
		t.Fatal("non-app symlink", code)
	}
}

func TestOverwriteOutput(t *testing.T) {
	root := testutil.App(t, false)
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "report.md")
	if e := os.WriteFile(path, []byte("old report"), 0644); e != nil {
		t.Fatal(e)
	}
	var out, err bytes.Buffer
	if code := Run([]string{root, "--output", path}, &out, &err); code != 0 {
		t.Fatal(code, err.String())
	}
	b, e := os.ReadFile(path)
	if e != nil || !bytes.Contains(b, []byte("# Underhood")) {
		t.Fatal(string(b), e)
	}
	if runtime.GOOS != "windows" {
		st, e := os.Stat(path)
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("replacement mode", st, e)
		}
	}
	assertNoTemps(t, dir)
	for _, p := range []string{dir, filepath.Join(root, "inside.md"), "/System/underhood-report.md"} {
		if _, e := destination(p, root); e == nil {
			t.Fatal("allowed unsafe destination", p)
		}
	}
	link := filepath.Join(dir, "link.md")
	if e := os.Symlink(path, link); e == nil {
		if _, e := destination(link, root); e == nil {
			t.Fatal("allowed symlink")
		}
	}
}
func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".underhood-") {
			t.Fatal("left temporary output", entry.Name())
		}
	}
}
func TestBothPartialFailure(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			dir := testutil.TempDir(t)
			first, second := filepath.Join(dir, "report.md"), filepath.Join(dir, "report.json")
			if existing {
				if e := os.WriteFile(first, []byte("old"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			calls := 0
			err := writeOutputs([]string{first, second}, [][]byte{[]byte("new"), []byte("json")}, func(p string, b []byte) error {
				calls++
				if calls == 2 {
					return fmt.Errorf("injected second-write failure")
				}
				return atomicWrite(p, b)
			})
			if err == nil {
				t.Fatal("expected failure")
			}
			b, e := os.ReadFile(first)
			if existing {
				if e != nil || string(b) != "new" {
					t.Fatal("removed replaced file", e, string(b))
				}
			} else if !os.IsNotExist(e) {
				t.Fatal("did not clean new file", e)
			}
			assertNoTemps(t, dir)
		})
	}
}
func TestBothPreflightAndRenameFailure(t *testing.T) {
	dir := testutil.TempDir(t)
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	if e := os.Mkdir(second, 0700); e != nil {
		t.Fatal(e)
	}
	if e := writeOutputs([]string{first, second}, [][]byte{[]byte("a"), []byte("b")}, atomicWrite); e == nil {
		t.Fatal("expected preflight refusal")
	}
	if _, e := os.Stat(first); !os.IsNotExist(e) {
		t.Fatal("first written before preflight")
	}
	// Force a failure after the temporary file was written and closed.
	if e := atomicWriteWithRename(first, []byte("report"), func(temp, dest string) error {
		b, e := os.ReadFile(temp)
		if e != nil || string(b) != "report" {
			t.Fatal("temp not written", e)
		}
		return fmt.Errorf("injected rename failure")
	}); e == nil {
		t.Fatal("expected rename failure")
	}
	assertNoTemps(t, dir)
}
