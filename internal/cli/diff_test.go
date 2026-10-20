package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/harinaralasetty/underhood/internal/diff"
	"github.com/harinaralasetty/underhood/internal/testutil"
)

func runDiff(t *testing.T, old, new string, flags ...string) diff.Report {
	t.Helper()
	args := append([]string{"diff", old, new, "--format", "json"}, flags...)
	var out, stderr bytes.Buffer
	if code := Run(args, &out, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	var r diff.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDiffAppVersions(t *testing.T) {
	old, new := testutil.AppVersions(t)
	r := runDiff(t, old, new)
	got := map[string]string{}
	for _, c := range r.Changes {
		got[c.ID] = c.Status
		if c.Old != nil && len(c.Old.Evidence) == 0 || c.New != nil && len(c.New.Evidence) == 0 {
			t.Fatal("missing evidence", c.ID)
		}
	}
	want := map[string]string{
		"bundle.CFBundleShortVersionString":                    "changed",
		"bundle.CFBundleVersion":                               "changed",
		"sign.flags":                                           "changed",
		"sign.team":                                            "changed",
		"ent.com.apple.security.get-task-allow":                "added",
		"ent.com.apple.security.network.client":                "changed",
		"privacy.NSCameraUsageDescription":                     "removed",
		"privacy.NSMicrophoneUsageDescription":                 "added",
		"url.scheme.fixture":                                   "removed",
		"url.scheme.fixture-new":                               "added",
		"launch.plist@Contents/Library/LaunchAgents/job.plist": "changed",
		"automation.NSAppleScriptEnabled":                      "changed",
		"automation.appintents@Contents/Resources/Metadata.appintents/extract.actionsdata":                     "added",
		"automation.action@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.inspect":       "added",
		"automation.intent@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.inspect.title": "added",
		"net.entitlement.com.apple.security.network.client":                                                    "changed",
		"net.host.api.fixture.test":                                      "changed",
		"net.host.retired.fixture.test":                                  "removed",
		"net.host.added.fixture.test":                                    "added",
		"bundle.CFBundleIdentifier@Contents/Frameworks/Helper.framework": "added",
		"bundle.CFBundleName@Contents/Frameworks/Helper.framework":       "added",
		"bundle.CFBundleVersion@Contents/Frameworks/Helper.framework":    "added",
		"sign.unsigned@Contents/Frameworks/Helper.framework":             "added",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected changes\ngot: %#v\nwant: %#v", got, want)
	}
	if r.SchemaVersion != 1 || r.Type != "diff" {
		t.Fatal(r)
	}
	if same := runDiff(t, old, old); len(same.Changes) != 0 {
		t.Fatal(same.Changes)
	}
	repeated := runDiff(t, old, new)
	repeated.ScannedAt = r.ScannedAt
	if !reflect.DeepEqual(r, repeated) {
		t.Fatal("repeated scans differ beyond scannedAt")
	}
	for _, full := range []bool{false, true} {
		var out, stderr bytes.Buffer
		args := []string{"diff", old, new, "--format", "markdown"}
		if full {
			args = append(args, "--full")
		}
		if code := Run(args, &out, &stderr); code != 0 {
			t.Fatal(code, &stderr)
		}
		for _, c := range r.Changes {
			if !strings.Contains(out.String(), c.ID) {
				t.Fatal("Markdown omitted change", c.ID)
			}
		}
	}
	// Reverse comparison preserves every ID and reverses additions/removals.
	reverse := runDiff(t, new, old)
	for _, c := range reverse.Changes {
		status := map[string]string{"added": "removed", "removed": "added", "changed": "changed"}[want[c.ID]]
		if c.Status != status {
			t.Fatal(c.ID, c.Status, status)
		}
	}
}

func TestDiffArgumentsAndOutputProtection(t *testing.T) {
	for _, args := range [][]string{{"diff"}, {"diff", "old"}, {"diff", "old", "new", "extra"}, {"diff", "old", "new", "--format", "both"}} {
		if _, err := Parse(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
	o, err := Parse([]string{"diff", "--full", "--format", "markdown", "--", "-old", "-new"})
	if err != nil || !o.Diff || !o.Full || o.OldPath != "-old" || o.Path != "-new" || o.Format != "md" {
		t.Fatal(o, err)
	}
	old, new := testutil.AppVersions(t)
	var out, stderr bytes.Buffer
	for _, args := range [][]string{{"diff", "missing", new}, {"diff", old, "missing"}} {
		if code := Run(args, &out, &stderr); code != 2 {
			t.Fatal(code, &stderr)
		}
	}
	for _, root := range []string{old, new} {
		inside := filepath.Join(root, "Contents", "Info.plist")
		before, err := os.ReadFile(inside)
		if err != nil {
			t.Fatal(err)
		}
		if code := Run([]string{"diff", old, new, "--output", inside}, &out, &stderr); code != 1 {
			t.Fatal("unsafe output allowed", code)
		}
		after, err := os.ReadFile(inside)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("target modified", err)
		}
		// Both outputs are preflighted against both targets, including aliases.
		alias := filepath.Join(testutil.TempDir(t), "alias")
		if err := os.Symlink(root, alias); err == nil {
			if code := Run([]string{"diff", old, new, "--format", "both", "--output", filepath.Join(alias, "report")}, &out, &stderr); code != 1 {
				t.Fatal("target alias allowed", code)
			}
		}
	}
	base := filepath.Join(testutil.TempDir(t), "comparison")
	if code := Run([]string{"diff", old, new, "--format", "both", "--output", base}, &out, &stderr); code != 0 {
		t.Fatal(code, &stderr)
	}
	for _, ext := range []string{".md", ".json"} {
		if _, err := os.Stat(base + ext); err != nil {
			t.Fatal(err)
		}
	}
	if code := Run([]string{"diff", "--help"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "underhood diff OLD NEW") {
		t.Fatal(code, &stderr)
	}
}

func TestDiffWindowsAndMismatch(t *testing.T) {
	dir := testutil.TempDir(t)
	old, new := filepath.Join(dir, "old.exe"), filepath.Join(dir, "new.exe")
	base := testutil.PEOptions{Version: map[string]string{"ProductName": "Fixture", "OriginalFilename": "fixture.exe", "ProductVersion": "1.0"}, Manifest: `<assembly><trustInfo><requestedExecutionLevel level="asInvoker"/></trustInfo></assembly>`}
	testutil.Write(t, old, testutil.PE(base))
	copy := filepath.Join(dir, "renamed.exe")
	testutil.Write(t, copy, testutil.PE(base))
	if renamed := runDiff(t, old, copy); len(renamed.Changes) != 0 {
		t.Fatal("root filename changed declarations", renamed.Changes)
	}
	base.Version["ProductVersion"] = "2.0"
	base.Manifest = strings.ReplaceAll(base.Manifest, "asInvoker", "requireAdministrator")
	base.Imports = map[string][]string{"winhttp.dll": {"WinHttpOpen"}}
	testutil.Write(t, new, testutil.PE(base))
	r := runDiff(t, old, new)
	got := map[string]string{}
	for _, c := range r.Changes {
		got[c.ID] = c.Status
	}
	for id, status := range map[string]string{"windows.version.ProductVersion": "changed", "windows.manifest.requestedExecutionLevel": "changed", "windows.imports.network": "added"} {
		if got[id] != status {
			t.Fatal(id, got)
		}
	}
	oldFolder, newFolder := filepath.Join(dir, "old-folder"), filepath.Join(dir, "new-folder")
	for folder, source := range map[string]string{oldFolder: old, newFolder: new} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Write(t, filepath.Join(folder, "app.exe"), data)
	}
	folderDiff := runDiff(t, oldFolder, newFolder)
	wantFolder, gotFolder := map[string]string{}, map[string]string{}
	for _, c := range r.Changes {
		wantFolder[c.ID+"@app.exe"] = c.Status
	}
	for _, c := range folderDiff.Changes {
		gotFolder[c.ID] = c.Status
	}
	if !reflect.DeepEqual(gotFolder, wantFolder) {
		t.Fatal(gotFolder, wantFolder)
	}
	mac := testutil.App(t, false)
	mismatch := runDiff(t, mac, new)
	if len(mismatch.Warnings) < 2 || !strings.Contains(strings.Join(mismatch.Warnings, " "), "Target kinds differ") || !strings.Contains(strings.Join(mismatch.Warnings, " "), "Target IDs differ") {
		t.Fatal(mismatch.Warnings)
	}
	// Same platform with a different bundle ID still produces a comparison.
	other := testutil.App(t, false)
	info := testutil.Info()
	info["CFBundleIdentifier"] = "org.test.other"
	testutil.Write(t, filepath.Join(other, "Contents", "Info.plist"), testutil.XML(info))
	if mismatch := runDiff(t, mac, other); !strings.Contains(strings.Join(mismatch.Warnings, " "), "Target IDs differ") {
		t.Fatal(mismatch.Warnings)
	}
	// Package capability and extension declarations use the same engine.
	oldPkg, newPkg := filepath.Join(dir, "old.msix"), filepath.Join(dir, "new.msix")
	testutil.Write(t, oldPkg, testutil.Zip(map[string][]byte{"AppxManifest.xml": []byte(testutil.AppxManifest)}))
	manifest := strings.ReplaceAll(testutil.AppxManifest, `<rescap:Capability Name="broadFileSystemAccess"/>`, "")
	manifest = strings.ReplaceAll(manifest, `Version="1.2.3.0"`, `Version="2.0.0.0"`)
	testutil.Write(t, newPkg, testutil.Zip(map[string][]byte{"AppxManifest.xml": []byte(manifest)}))
	pkg := runDiff(t, oldPkg, newPkg)
	want := map[string]string{"windows.msix.identity": "changed", "windows.msix.restricted.broadFileSystemAccess": "removed"}
	got = map[string]string{}
	for _, c := range pkg.Changes {
		got[c.ID] = c.Status
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MSIX changes: %#v", got)
	}
}

func TestDiffCapAndMalformedSide(t *testing.T) {
	old, new := testutil.App(t, false), testutil.App(t, false)
	binary := filepath.Join(new, "Contents", "MacOS", "Fixture")
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, make([]byte, 1<<20)...)
	data = append(data, []byte("https://beyond-cap.fixture.test/a\x00")...)
	testutil.Write(t, binary, data)
	r := runDiff(t, old, new, "--max-binary-mb", "1")
	capOnSide := func(s diff.Snapshot) bool {
		for _, note := range s.Skipped {
			if strings.Contains(note.Reason, "binary-scan cap of 1 MiB reached") {
				return true
			}
		}
		return false
	}
	if capOnSide(r.Old) || !capOnSide(r.New) || len(r.Changes) != 0 {
		t.Fatal(r)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "not proof of absence") {
		t.Fatal(r.Warnings)
	}
	testutil.Write(t, filepath.Join(new, "Contents", "Info.plist"), []byte("<plist><dict><key>broken"))
	r = runDiff(t, old, new, "--no-binary-strings")
	if len(r.New.Skipped) == 0 || len(r.Changes) == 0 {
		t.Fatal("malformed metadata was not disclosed", r)
	}
	var out, stderr bytes.Buffer
	if code := Run([]string{"diff", old, new}, failWriter{}, &stderr); code != 1 {
		t.Fatal("write error not propagated", code)
	}
	if code := Run([]string{"diff", old, new, "--format", "json"}, &out, &stderr); code != 0 {
		t.Fatal(code, &stderr)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }
