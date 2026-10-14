package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harinaralasetty/underhood/internal/testutil"
)

func TestWindowsCLI(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.bin")
	invalid := filepath.Join(dir, "invalid.exe")
	for path, data := range map[string][]byte{valid: testutil.PE(testutil.PEOptions{}), invalid: []byte("MZ not a PE")} {
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, tt := range []struct {
		path string
		code int
	}{{valid, 0}, {invalid, 2}} {
		var out, err bytes.Buffer
		code := Run([]string{tt.path, "--format", "json"}, &out, &err)
		if code != tt.code {
			t.Fatalf("code=%d out=%s err=%s", code, &out, &err)
		}
		if code == 0 && !strings.Contains(out.String(), `"kind": "windows-pe"`) {
			t.Fatal(out.String())
		}
		if code == 2 && !strings.Contains(err.String(), "windows-folder") {
			t.Fatal(err.String())
		}
	}
}

func TestMSIXCLI(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		code int
		kind string
	}{
		{"package.bin", testutil.MSIX(nil), 0, "windows-msix"},
		{"bundle.bin", testutil.MSIXBundle(testutil.MSIX(nil)), 0, "windows-msix"},
		{"fake.msix", []byte("not a zip"), 2, ""},
		{"ordinary.zip", testutil.Zip(map[string][]byte{"hello": []byte("world")}), 2, ""},
		{"bad-xml.msix", testutil.Zip(map[string][]byte{"AppxManifest.xml": []byte("invalid")}), 0, "windows-msix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), tc.name)
			if e := os.WriteFile(p, tc.data, 0600); e != nil {
				t.Fatal(e)
			}
			var out, err bytes.Buffer
			code := Run([]string{p, "--format", "json"}, &out, &err)
			if code != tc.code {
				t.Fatalf("code %d: %s %s", code, &out, &err)
			}
			if code == 0 && !strings.Contains(out.String(), `"kind": "`+tc.kind+`"`) {
				t.Fatal(out.String())
			}
			if code == 2 && !strings.Contains(err.String(), "windows-msix") {
				t.Fatal(err.String())
			}
		})
	}
}
