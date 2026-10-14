package windows

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/testutil"
)

func TestPECore(t *testing.T) {
	for _, pe32 := range []bool{false, true} {
		b := testutil.PE(testutil.PEOptions{PE32: pe32, Managed: true, Imports: map[string][]string{"kernel32.dll": {"OpenProcess", "LoadLibraryW"}, "winhttp.dll": {"WinHttpOpen"}}})
		if !DetectPE(bytes.NewReader(b), int64(len(b))) {
			t.Fatal("detection failed")
		}
		f, s := AnalyzePE(bytes.NewReader(b), int64(len(b)), "child.exe", model.Options{})
		if len(s) > 0 {
			t.Fatalf("skips: %+v", s)
		}
		ids := map[string]model.Finding{}
		for _, v := range f {
			ids[v.ID] = v
		}
		for _, id := range []string{"windows.identity.managed", "windows.imports.process", "windows.imports.network", "windows.imports.dynamic", "windows.pe.unsigned", "windows.hardening.cfg"} {
			v, ok := ids[id+"@child.exe"]
			if !ok {
				t.Errorf("missing %s", id)
			}
			if len(v.Evidence) == 0 || v.Evidence[0].File != "child.exe" {
				t.Errorf("bad evidence: %+v", v)
			}
		}
		if ids["windows.imports.process@child.exe"].Confidence != model.Heuristic {
			t.Error("import confidence")
		}
	}
}
func TestPEBounds(t *testing.T) {
	b := testutil.PE(testutil.PEOptions{})
	for _, n := range []int{0, 2, 63, 95, 128, 200, 511, len(b) - 1} {
		if _, e := openPE(bytes.NewReader(b[:n]), int64(n)); e == nil {
			t.Errorf("accepted truncation %d", n)
		}
	}
	for _, tc := range []struct {
		off   int
		value uint32
	}{{60, 0xffffffff}, {140, 0xffffffff}, {144, 0xffffffff}, {152 + 240 + 20, 0xffffffff}} {
		c := append([]byte(nil), b...)
		binary.LittleEndian.PutUint32(c[tc.off:], tc.value)
		if _, e := openPE(bytes.NewReader(c), int64(len(c))); e == nil {
			t.Errorf("accepted corruption at %d", tc.off)
		}
	}
	efi := testutil.PE(testutil.PEOptions{Subsystem: 10, DLL: true})
	if DetectPE(bytes.NewReader(efi), int64(len(efi))) {
		t.Error("accepted EFI")
	}
}
func TestPEStrings(t *testing.T) {
	b := testutil.PE(testutil.PEOptions{})
	b = append(b, []byte("\x00https://real.test/path\x00\\CurrentVersion\\Run\x00")...)
	for _, c := range []byte("https://wide.test/path") {
		b = append(b, c, 0)
	}
	b = append(b, 0, 0)
	f, _ := analyzeStrings(bytes.NewReader(b), int64(len(b)), "", model.Options{BinaryStrings: true})
	urls := 0
	paths := 0
	for _, v := range f {
		if v.Category == "network" {
			urls++
		}
		if v.Category == "capabilities" && v.Severity == model.Notable {
			paths++
		}
	}
	if urls != 2 || paths != 1 {
		t.Fatalf("urls=%d paths=%d: %+v", urls, paths, f)
	}
}

func TestPEEndpointGrouping(t *testing.T) {
	data := []byte("https://real.test/one\x00https://real.test/two\x00")
	f, s := analyzeStrings(bytes.NewReader(data), int64(len(data)), "a.exe", model.Options{BinaryStrings: true})
	if len(s) != 0 || len(f) != 1 {
		t.Fatalf("findings=%+v skips=%+v", f, s)
	}
	if f[0].ID != "net.host.real.test" || len(f[0].Evidence) != 2 || f[0].Evidence[0].File != "a.exe" || f[0].Severity != model.Notable || f[0].Confidence != model.Binary {
		t.Fatalf("bad endpoint group: %+v", f[0])
	}
}
