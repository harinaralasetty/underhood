package macos

import (
	"errors"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/report"
	"github.com/harinaralasetty/underhood/internal/target"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFixtureAndDeterminism(t *testing.T) {
	for _, binary := range []bool{false, true} {
		root := testutil.App(t, binary)
		ctx := target.Context{Root: root, Options: model.Options{MaxBinaryMB: 300, BinaryStrings: true}}
		a, e := (App{}).Analyze(ctx)
		if e != nil {
			t.Fatal(e)
		}
		b, e := (App{}).Analyze(ctx)
		if e != nil {
			t.Fatal(e)
		}
		ra, rb := report.Build(a), report.Build(b)
		ra.ScannedAt = ""
		rb.ScannedAt = ""
		if !reflect.DeepEqual(ra, rb) {
			t.Fatal("nondeterministic report")
		}
		want := map[string]struct {
			cat  string
			sev  model.Severity
			conf model.Confidence
		}{"bundle.sandbox": {"identity", model.Info, model.Declared}, "sign.flags": {"signing", model.Info, model.Declared}, "privacy.NSCameraUsageDescription": {"permissions", model.Notable, model.Declared}, "ent.com.apple.security.cs.disable-library-validation": {"entitlements", model.Sensitive, model.Declared}, "url.scheme.fixture": {"registrations", model.Notable, model.Declared}, "launch.plist@Contents/Library/LaunchAgents/job.plist": {"launchItems", model.Notable, model.Declared}, "automation.sdef.command.inspect@Contents/Resources/Fixture.sdef": {"automation", model.Notable, model.Declared}, "net.host.utf16.test": {"network", model.Notable, model.Binary}}
		for _, f := range ra.Findings {
			if len(f.Evidence) == 0 {
				t.Fatal("missing evidence", f.ID)
			}
			if w, ok := want[f.ID]; ok {
				if f.Category != w.cat || f.Severity != w.sev || f.Confidence != w.conf {
					t.Fatalf("wrong finding %+v", f)
				}
				delete(want, f.ID)
			}
		}
		if len(want) > 0 {
			t.Fatal("missing", want)
		}
	}
}

// A target below the home directory must still yield bundle-relative IDs and evidence paths.
func TestTargetUnderHomeKeepsRelativeIDs(t *testing.T) {
	root := testutil.App(t, false)
	t.Setenv("HOME", filepath.Dir(root))
	t.Setenv("USERPROFILE", filepath.Dir(root))
	r, e := (App{}).Analyze(target.Context{Root: root, Options: model.Options{MaxBinaryMB: 300, BinaryStrings: true}})
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range r.Findings {
		if f.ID == "launch.plist@Contents/Library/LaunchAgents/job.plist" {
			return
		}
	}
	t.Fatal("relative launch.plist ID missing when target is under home")
}
func TestFailureContinues(t *testing.T) {
	root := testutil.App(t, false)
	ran := false
	r, e := analyze(target.Context{Root: root}, []Analyzer{{"injected", func(*context) error { return errors.New("injected failure") }}, {"panic", func(*context) error { panic("injected panic") }}, {"after", func(*context) error { ran = true; return nil }}})
	if e != nil || !ran || len(r.Skipped) < 2 {
		t.Fatal(r, e, ran)
	}
}
func TestMalformedMetadataContinues(t *testing.T) {
	root := testutil.App(t, false)
	testutil.Write(t, filepath.Join(root, "Contents", "Info.plist"), []byte("broken"))
	r, e := (App{}).Analyze(target.Context{Root: root, Options: model.Options{MaxBinaryMB: 1}})
	if e != nil || len(r.Skipped) == 0 {
		t.Fatal(r, e)
	}
}
