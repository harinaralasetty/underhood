package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/harinaralasetty/underhood/internal/model"
)

func testVersionBlock(key, value string, children ...[]byte) []byte {
	b := make([]byte, 6)
	for _, u := range utf16.Encode([]rune(key + "\x00")) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	v := utf16.Encode([]rune(value + "\x00"))
	if value == "" {
		v = nil
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(v)))
	binary.LittleEndian.PutUint16(b[4:], 1)
	for _, u := range v {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	for _, child := range children {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		b = append(b, child...)
	}
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	return b
}
func TestVersionStringsAndTruncation(t *testing.T) {
	b := testVersionBlock("VS_VERSION_INFO", "", testVersionBlock("StringFileInfo", "", testVersionBlock("040904b0", "", testVersionBlock("ProductName", "Demo"), testVersionBlock("OriginalFilename", "demo.exe"))))
	fs, e := decodeVersion(b, "demo.exe", ".rsrc/RT_VERSION/1/1033")
	if e != nil {
		t.Fatal(e)
	}
	if len(fs) != 2 || fs[0].ID != "windows.version.ProductName@demo.exe" || fs[0].Evidence[0].Value != "Demo" {
		t.Fatalf("%+v", fs)
	}
	for i := 0; i < len(b); i++ {
		if _, e := decodeVersion(b[:i], "", ""); e == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}
func TestResourceWalkerBounds(t *testing.T) {
	b := make([]byte, 88)
	for i := 0; i < 3; i++ {
		off := i * 24
		binary.LittleEndian.PutUint16(b[off+14:], 1)
		binary.LittleEndian.PutUint32(b[off+16:], uint32([]int{24, 1, 1033}[i]))
		dest := uint32(off+24) | 0x80000000
		if i == 2 {
			dest = 72
		}
		binary.LittleEndian.PutUint32(b[off+20:], dest)
	}
	binary.LittleEndian.PutUint32(b[72:], 0x1000)
	binary.LittleEndian.PutUint32(b[76:], 8)
	calls := 0
	visit := func(k uint32, p string, r, n uint32) error {
		calls++
		if k != 24 || p != ".rsrc/RT_MANIFEST/1/1033" {
			t.Fatalf("%d %s", k, p)
		}
		return nil
	}
	if e := walkResources(b, visit); e != nil || calls != 1 {
		t.Fatalf("%v %d", e, calls)
	}
	for i := 0; i < len(b); i++ {
		if e := walkResources(b[:i], visit); e == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	binary.LittleEndian.PutUint32(b[20:], 0x80000000)
	if e := walkResources(b, visit); e == nil {
		t.Fatal("accepted cycle")
	}
}
func TestPEManifest(t *testing.T) {
	data := []byte(`<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><trustInfo><requestedExecutionLevel level="requireAdministrator" uiAccess="true"/></trustInfo><application><windowsSettings><autoElevate>true</autoElevate><longPathAware>true</longPathAware><dpiAwareness>PerMonitorV2</dpiAwareness></windowsSettings></application><compatibility><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></compatibility><dependency><dependentAssembly><assemblyIdentity name="Microsoft.Windows.Common-Controls" version="6.0.0.0"/></dependentAssembly></dependency></assembly>`)
	fs, e := parsePEManifest(data, "demo.exe", ".rsrc/RT_MANIFEST/1/1033")
	if e != nil {
		t.Fatal(e)
	}
	if len(fs) != 7 || fs[0].Severity != model.Sensitive || fs[0].Confidence != model.Declared || !strings.Contains(fs[5].Detail, "Windows 10/11") {
		t.Fatalf("%+v", fs)
	}
	for _, bad := range []string{"", "<a>", "<a/><b/>", "<a>" + strings.Repeat("<b>", 65), "<a>" + strings.Repeat("x", 65537) + "</a>"} {
		if _, e := parsePEManifest([]byte(bad), "", ""); e == nil {
			t.Fatal("accepted malformed XML")
		}
	}
}
func FuzzResourceWalker(f *testing.F) {
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > resourceLimit {
			return
		}
		_ = walkResources(b, func(uint32, string, uint32, uint32) error { return nil })
		_, _ = decodeVersion(b, "", "")
	})
}
func FuzzPEManifest(f *testing.F) {
	f.Add([]byte(`<assembly><requestedExecutionLevel level="asInvoker"/></assembly>`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parsePEManifest(b, "", "") })
}

func TestSharedPEResources(t *testing.T) {
	for _, small := range []bool{false, true} {
		b := testutil.PE(testutil.PEOptions{PE32: small, Manifest: `<assembly><requestedExecutionLevel level="highestAvailable"/></assembly>`, Version: map[string]string{"ProductName": "Portable Demo", "FileVersion": "1.2.3"}})
		p, e := pe.NewFile(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		fs, skips := analyzeResources(bytes.NewReader(b), int64(len(b)), p, "")
		p.Close()
		if len(skips) != 0 || len(fs) != 3 {
			t.Fatalf("findings=%+v skips=%+v", fs, skips)
		}
		for _, f := range fs {
			if f.Evidence[0].File != "." {
				t.Fatal(f)
			}
		}
	}
}

func TestFixedVersionInfo(t *testing.T) {
	b := testVersionBlock("VS_VERSION_INFO", "")
	binary.LittleEndian.PutUint16(b[2:], 52)
	binary.LittleEndian.PutUint16(b[4:], 0)
	fixed := make([]byte, 52)
	binary.LittleEndian.PutUint32(fixed, 0xfeef04bd)
	binary.LittleEndian.PutUint32(fixed[8:], 1<<16|2)
	binary.LittleEndian.PutUint32(fixed[12:], 3<<16|4)
	b = append(b, fixed...)
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	fs, e := decodeVersion(b, "", "")
	if e != nil || len(fs) != 2 || fs[0].Evidence[0].Value != "1.2.3.4" {
		t.Fatalf("%+v %v", fs, e)
	}
	b[40] = 0
	if _, e := decodeVersion(b, "", ""); e == nil {
		t.Fatal("accepted bad fixed signature")
	}
}
