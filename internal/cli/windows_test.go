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
