package windows

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/target"
	"github.com/harinaralasetty/underhood/internal/testutil"
)

func writePE(t *testing.T, p string) {
	t.Helper()
	if e := os.WriteFile(p, testutil.PE(testutil.PEOptions{}), 0600); e != nil {
		t.Fatal(e)
	}
}
func canonicalTemp(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestWindowsTargets(t *testing.T) {
	root := canonicalTemp(t)
	p := filepath.Join(root, "image.no-extension")
	writePE(t, p)
	r, e := target.Analyze(p, model.Options{})
	if e != nil || r.Target.Kind != "windows-pe" {
		t.Fatalf("%+v %v", r.Target, e)
	}
	if ok, _ := (Folder{}).Detect(root); !ok {
		t.Fatal("folder not detected")
	}
	r, e = (Folder{}).Analyze(target.Context{Root: root})
	if e != nil || len(r.Findings) == 0 {
		t.Fatalf("%+v %v", r, e)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "windows.identity.machine@image.no-extension" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing namespaced finding")
	}
	if e := os.WriteFile(filepath.Join(root, "AppxManifest.xml"), []byte("not parsed in B1"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e = (Folder{}).Analyze(target.Context{Root: root})
	if e != nil || len(r.Findings) != 0 || len(r.Skipped) != 1 || r.Skipped[0].Reason != "MSIX folder analysis arrives in a later release" {
		t.Fatalf("MSIX skip: %+v %v", r, e)
	}
}
func TestFolderDepthSymlinkAndCap(t *testing.T) {
	root := canonicalTemp(t)
	if e := os.MkdirAll(filepath.Join(root, "one", "two"), 0700); e != nil {
		t.Fatal(e)
	}
	writePE(t, filepath.Join(root, "one", "one.exe"))
	writePE(t, filepath.Join(root, "one", "two", "ignored.exe"))
	if e := os.Symlink(filepath.Join(root, "one", "one.exe"), filepath.Join(root, "linked.exe")); e != nil {
		t.Skip(e)
	}
	files, notes := folderFiles(root, false)
	if len(files) != 1 || len(notes) != 1 {
		t.Fatalf("files=%v notes=%v", files, notes)
	}
	for i := 0; i < 22; i++ {
		writePE(t, filepath.Join(root, string(rune('a'+i))+".exe"))
	}
	r, e := (Folder{}).Analyze(target.Context{Root: root})
	if e != nil {
		t.Fatal(e)
	}
	machines, listed := 0, 0
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "windows.identity.machine@") {
			machines++
		}
	}
	for _, n := range r.Skipped {
		if strings.Contains(n.Reason, "listed only") {
			listed++
		}
	}
	if machines != 20 || listed != 3 {
		t.Fatalf("analysed=%d listed=%d", machines, listed)
	}
	again, _ := (Folder{}).Analyze(target.Context{Root: root})
	if model.Text(r) != model.Text(again) {
		t.Fatal("nondeterministic folder analysis")
	}
}

func TestFolderCapIgnoresCreationOrder(t *testing.T) {
	root := canonicalTemp(t)
	for i := 209; i >= 0; i-- {
		writePE(t, filepath.Join(root, fmt.Sprintf("%03d.exe", i)))
	}
	files, notes := folderFiles(root, false)
	if len(files) != 200 || len(notes) == 0 {
		t.Fatalf("%d files %v", len(files), notes)
	}
	if filepath.Base(files[0].path) != "000.exe" || filepath.Base(files[199].path) != "199.exe" {
		t.Fatalf("%s to %s", files[0].path, files[199].path)
	}
}

func TestFolderEndpointBudget(t *testing.T) {
	r := target.Result{}
	for i := 0; i < 205; i++ {
		for j := 0; j < 21; j++ {
			r.Findings = append(r.Findings, model.Finding{ID: fmt.Sprintf("net.host.%03d.test", i), Evidence: []model.Evidence{{File: fmt.Sprintf("%d.exe", j), Value: "https://host.test"}}})
		}
	}
	capFolderHosts(&r)
	if len(r.Findings) != 200 || len(r.Skipped) != 1 {
		t.Fatalf("findings=%d skipped=%v", len(r.Findings), r.Skipped)
	}
	for _, f := range r.Findings {
		if len(f.Evidence) != 20 {
			t.Fatal(len(f.Evidence))
		}
	}
}

func TestPEIdentityAndSignedFixture(t *testing.T) {
	cert, e := testutil.PKCS7()
	if e != nil {
		t.Fatal(e)
	}
	root := canonicalTemp(t)
	p := filepath.Join(root, "fixture.exe")
	b := testutil.PE(testutil.PEOptions{Certificate: cert, Manifest: `<assembly><requestedExecutionLevel level="requireAdministrator" uiAccess="true"/></assembly>`, Version: map[string]string{"ProductName": "Fixture Product", "OriginalFilename": "original.exe", "FileVersion": "2.3.4.5"}})
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := (PE{}).Analyze(target.Context{Root: p})
	if e != nil {
		t.Fatal(e)
	}
	if r.Target.Name != "Fixture Product" || r.Target.ID != "original.exe" || r.Target.Version != "2.3.4.5" {
		t.Fatal(r.Target)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "windows.pe.signature" {
			found = true
		}
		if f.ID == "windows.pe.unsigned" {
			t.Fatal("signed fixture reported unsigned")
		}
	}
	if !found || len(r.Skipped) != 0 {
		t.Fatalf("signature=%t skips=%v", found, r.Skipped)
	}
}
