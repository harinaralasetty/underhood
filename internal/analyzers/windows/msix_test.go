package windows

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/report"
	"github.com/harinaralasetty/underhood/internal/target"
	"github.com/harinaralasetty/underhood/internal/testutil"
)

func scanPackage(b []byte) target.Result {
	r := initial("synthetic.msix", "windows-msix")
	s := packageScan{result: &r, opts: model.Options{MaxBinaryMB: 1, BinaryStrings: true}, remaining: maxPackageBytes}
	s.archive(bytes.NewReader(b), int64(len(b)), "", false)
	return r
}
func TestMSIXPackage(t *testing.T) {
	sig, e := testutil.PKCS7()
	if e != nil {
		t.Fatal(e)
	}
	b := testutil.MSIX(sig)
	r := report.Build(scanPackage(b))
	if r.Target.ID != "Underhood.Synthetic" || r.Target.Name != "Synthetic Windows App" || r.Target.Version != "1.2.3.0" {
		t.Fatal(r.Target)
	}
	if len(r.Skipped) > 0 {
		t.Fatal(r.Skipped)
	}
	wants := map[string]struct {
		cat string
		sev model.Severity
	}{
		"windows.msix.restricted.runFullTrust":         {"capabilities", model.Sensitive},
		"windows.msix.capability.internetClient":       {"capabilities", model.Notable},
		"windows.msix.capability.microphone":           {"capabilities", model.Notable},
		"windows.msix.capability.Synthetic.Custom":     {"capabilities", model.Info},
		"windows.msix.extension.windows.service":       {"windows-manifest", model.Sensitive},
		"windows.msix.extension.windows.startupTask":   {"windows-manifest", model.Notable},
		"windows.msix.extension.windows.firewallRules": {"windows-manifest", model.Notable},
		"windows.msix.signature":                       {"signing", model.Info},
		"windows.identity.machine@bin/app.exe":         {"identity", model.Info},
		"windows.pe.unsigned@bin/app.exe":              {"signing", model.Notable},
	}
	for _, f := range r.Findings {
		if w, ok := wants[f.ID]; ok {
			if f.Category != w.cat || f.Severity != w.sev || f.Confidence != model.Declared || len(f.Evidence) == 0 {
				t.Fatalf("%+v", f)
			}
			delete(wants, f.ID)
		}
		if f.ID == "windows.msix.publisher-mismatch" {
			t.Fatal("matching publisher flagged")
		}
	}
	if len(wants) > 0 {
		t.Fatal("missing", wants)
	}
	r2 := report.Build(scanPackage(b))
	r2.ScannedAt = r.ScannedAt
	if !reflect.DeepEqual(r, r2) {
		t.Fatal("nondeterministic")
	}
	found := false
	for _, s := range r.Summary {
		if strings.Contains(s.Text, "2 restricted capabilities") {
			found = true
		}
	}
	if !found {
		t.Fatal(r.Summary)
	}
}
func TestMSIXBundle(t *testing.T) {
	r := scanPackage(testutil.MSIXBundle(testutil.MSIX(nil)))
	if r.Target.ID != "Underhood.Bundle" {
		t.Fatal(r.Target)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "windows.identity.machine@app.msix/bin/app.exe" {
			found = true
		}
		if strings.Contains(f.ID, "@resources.msix") {
			t.Fatal(f)
		}
	}
	if !found || len(r.Skipped) > 0 {
		t.Fatal(r.Skipped)
	}
	nested := scanPackage(testutil.MSIXBundle(testutil.MSIXBundle(testutil.MSIX(nil))))
	if !notesContain(nested, "nested bundle") {
		t.Fatal(nested.Skipped)
	}
}
func notesContain(r target.Result, s string) bool {
	for _, n := range r.Skipped {
		if strings.Contains(n.Reason, s) {
			return true
		}
	}
	return false
}
func TestAppxFolder(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), []byte(testutil.AppxManifest), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(dir, "bin"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "bin", "app.exe"), testutil.PE(testutil.PEOptions{}), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := target.Analyze(dir, model.Options{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Target.Kind != "windows-folder" || r.Target.ID != "Underhood.Synthetic" || len(r.Skipped) != 0 {
		t.Fatal(r)
	}
	if e := os.Remove(filepath.Join(dir, "bin", "app.exe")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(dir, "AppxManifest.xml"), filepath.Join(dir, "bin", "app.exe")); e != nil {
		t.Skip(e)
	}
	r, e = target.Analyze(dir, model.Options{})
	if e != nil || !notesContain(r, "symlinks") {
		t.Fatal(e, r.Skipped)
	}
}
func TestAppxManifestCorruption(t *testing.T) {
	for _, b := range []string{"", `<Package>`, `<Other/>`, `<Package/><Package/>`, `text<Package/>`, `<!DOCTYPE Package><Package/>`, `<Package><Application Executable="a" x:Executable="b"/></Package>`, strings.Repeat("<Package>", 65) + strings.Repeat("</Package>", 65), "<Package>" + strings.Repeat("x", 65537) + "</Package>"} {
		if _, e := parseAppxManifest([]byte(b), "AppxManifest.xml", "", false); e == nil {
			t.Fatalf("accepted %.80s", b)
		}
	}
	b := []byte(testutil.AppxManifest)
	for i := 0; i < len(b); i += 71 {
		if _, e := parseAppxManifest(b[:i], "AppxManifest.xml", "", false); e == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}
func TestMSIXUnsafeAndCaps(t *testing.T) {
	entries := map[string][]byte{"AppxManifest.xml": []byte(`<Package><Applications><Application Executable="../escape.exe"/></Applications></Package>`), "../escape.exe": testutil.PE(testutil.PEOptions{}), "/absolute.exe": []byte("bad"), "C:/drive.exe": []byte("bad")}
	r := scanPackage(testutil.Zip(entries))
	if !notesContain(r, "unsafe") {
		t.Fatal(r.Skipped)
	}
	entries = map[string][]byte{"AppxManifest.xml": []byte(`<Package/>`)}
	for i := 0; i < 22; i++ {
		entries[fmt.Sprintf("%02d.exe", i)] = testutil.PE(testutil.PEOptions{})
	}
	r = scanPackage(testutil.Zip(entries))
	n := 0
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "windows.identity.machine@") {
			n++
		}
	}
	if n != 20 || !notesContain(r, "20 PE") {
		t.Fatal(n, r.Skipped)
	}
	b := testutil.MSIX(nil)
	bad := append([]byte(nil), b...)
	pos := bytes.Index(bad, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint32(bad[pos+24:], maxZipEntry+1)
	r = scanPackage(bad)
	if !notesContain(r, "read cap") {
		t.Fatal(r.Skipped)
	}
	entries = map[string][]byte{"AppxManifest.xml": []byte(`<Package/>`), "APPXMANIFEST.XML": []byte(`<Package/>`)}
	r = scanPackage(testutil.Zip(entries))
	if !notesContain(r, "duplicate") {
		t.Fatal(r.Skipped)
	}
	for i := 0; i < len(b); i += 127 {
		r = scanPackage(b[:i])
		if len(r.Skipped) == 0 {
			t.Fatalf("truncation %d", i)
		}
	}
	bad = append([]byte(nil), b...)
	binary.LittleEndian.PutUint16(bad[len(bad)-12:], 20001)
	if _, e := packageZip(bytes.NewReader(bad), int64(len(bad))); e == nil {
		t.Fatal("entry count accepted")
	}
}
func TestMSIXReadBounds(t *testing.T) {
	b := testutil.Zip(map[string][]byte{"large": bytes.Repeat([]byte("a"), 4096)})
	z, e := packageZip(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	s := packageScan{remaining: 2048}
	if _, e = s.read(z.File[0], "", maxZipEntry); e == nil {
		t.Fatal("aggregate bound")
	}
	s.remaining = maxPackageBytes
	if _, e = s.read(z.File[0], "", 1024); e == nil {
		t.Fatal("entry bound")
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	h := &zip.FileHeader{Name: "AppxManifest.xml"}
	h.SetMode(os.ModeSymlink | 0777)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("elsewhere"))
	zw.Close()
	if !notesContain(scanPackage(out.Bytes()), "non-regular") {
		t.Fatal("zip symlink")
	}
}
func TestMSIXSignatureStates(t *testing.T) {
	sig, e := testutil.PKCS7()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		sig           []byte
		publisher, id string
	}{{nil, "", "unsigned"}, {[]byte("bad"), "", "signature-unparsable"}, {sig, "CN=Someone else", "publisher-mismatch"}} {
		entries := map[string][]byte{"AppxManifest.xml": []byte(`<Package><Identity Publisher="` + tc.publisher + `"/></Package>`)}
		if tc.sig != nil {
			entries["AppxSignature.p7x"] = append([]byte("PKCX"), tc.sig...)
		}
		r := scanPackage(testutil.Zip(entries))
		found := false
		for _, f := range r.Findings {
			if f.ID == "windows.msix."+tc.id {
				found = true
			}
		}
		if !found {
			t.Fatal(tc.id, r.Findings)
		}
	}
}
func TestWriteMSIXExample(t *testing.T) {
	p := os.Getenv("UNDERHOOD_MSIX_FIXTURE")
	if p == "" {
		t.Skip("set UNDERHOOD_MSIX_FIXTURE to write the synthetic example package")
	}
	sig, e := testutil.PKCS7()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, testutil.MSIX(sig), 0600); e != nil {
		t.Fatal(e)
	}
}
func FuzzAppxManifest(f *testing.F) {
	f.Add([]byte(testutil.AppxManifest))
	f.Add([]byte(`<Bundle/>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseAppxManifest(b, "AppxManifest.xml", "", false)
		parseAppxManifest(b, "AppxBundleManifest.xml", "", true)
	})
}
func FuzzMSIXZip(f *testing.F) {
	f.Add(testutil.MSIX(nil))
	f.Add(testutil.MSIXBundle(testutil.MSIX(nil)))
	f.Add(testutil.Zip(map[string][]byte{"AppxManifest.xml": []byte(`<Package/>`)}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		scanPackage(b)
	})
}

func TestBundleApplicationCap(t *testing.T) {
	entries := map[string][]byte{}
	var manifest strings.Builder
	manifest.WriteString(`<Bundle><Packages>`)
	for i := 0; i < 6; i++ {
		name := fmt.Sprintf("%d.msix", i)
		fmt.Fprintf(&manifest, `<Package FileName="%s" Type="application"/>`, name)
		entries[name] = testutil.MSIX(nil)
	}
	manifest.WriteString(`</Packages></Bundle>`)
	entries["AppxBundleManifest.xml"] = []byte(manifest.String())
	r := scanPackage(testutil.Zip(entries))
	n := 0
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "windows.msix.identity@") {
			n++
		}
	}
	if n != 4 || !notesContain(r, "4 application-package") {
		t.Fatal(n, r.Skipped)
	}
}

func TestManifestEvidence(t *testing.T) {
	r := report.Build(scanPackage(testutil.MSIX(nil)))
	want := map[string]string{"windows.protocol": "Name=synthetic", "windows.fileTypeAssociation": ".synthetic", "windows.startupTask": "Enabled=true", "windows.appExecutionAlias": "Alias=synthetic.exe", "windows.service": "StartAccount=localSystem", "windows.firewallRules": "LocalPortMin=4242", "windows.appUriHandler": "Name=synthetic.example.org", "windows.backgroundTasks": "Type=timer", "windows.comServer": "Executable=bin", "windows.shareTarget": "Text", "windows.appService": "Name=SyntheticAppService", "windows.fullTrustProcess": "Executable=bin", "windows.syntheticUnknown": "Name=raw"}
	for _, f := range r.Findings {
		key := strings.TrimPrefix(f.ID, "windows.msix.extension.")
		if value, ok := want[key]; ok {
			for _, ev := range f.Evidence {
				if strings.Contains(ev.Value, value) && ev.File == "AppxManifest.xml" {
					delete(want, key)
				}
			}
		}
	}
	if len(want) > 0 {
		t.Fatal(want)
	}
}

func TestZipDirectoryPreflight(t *testing.T) {
	original := testutil.MSIX(nil)
	end := len(original) - 22
	// An underreported directory must not let archive/zip read extra records.
	bad := append([]byte(nil), original...)
	binary.LittleEndian.PutUint16(bad[end+8:], 0)
	binary.LittleEndian.PutUint16(bad[end+10:], 0)
	binary.LittleEndian.PutUint32(bad[end+12:], 0)
	if _, e := packageZip(bytes.NewReader(bad), int64(len(bad))); e == nil {
		t.Fatal("underreported directory accepted")
	}
	// Convert the ordinary end record to a minimal ZIP64 directory.
	z64 := make([]byte, 56)
	copy(z64, "PK\x06\x06")
	binary.LittleEndian.PutUint64(z64[4:], 44)
	count := uint64(binary.LittleEndian.Uint16(original[end+10:]))
	binary.LittleEndian.PutUint64(z64[24:], count)
	binary.LittleEndian.PutUint64(z64[32:], count)
	binary.LittleEndian.PutUint64(z64[40:], uint64(binary.LittleEndian.Uint32(original[end+12:])))
	binary.LittleEndian.PutUint64(z64[48:], uint64(binary.LittleEndian.Uint32(original[end+16:])))
	loc := make([]byte, 20)
	copy(loc, "PK\x06\x07")
	binary.LittleEndian.PutUint64(loc[8:], uint64(end))
	binary.LittleEndian.PutUint32(loc[16:], 1)
	last := append([]byte(nil), original[end:]...)
	binary.LittleEndian.PutUint16(last[8:], 65535)
	binary.LittleEndian.PutUint16(last[10:], 65535)
	binary.LittleEndian.PutUint32(last[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(last[16:], 0xffffffff)
	b := append(append(append(append([]byte(nil), original[:end]...), z64...), loc...), last...)
	if _, e := packageZip(bytes.NewReader(b), int64(len(b))); e != nil {
		t.Fatal(e)
	}
	if len(scanPackage(b).Skipped) > 0 {
		t.Fatal(scanPackage(b).Skipped)
	}
	binary.LittleEndian.PutUint64(b[end+32:], 20001)
	if _, e := packageZip(bytes.NewReader(b), int64(len(b))); e == nil {
		t.Fatal("ZIP64 count cap")
	}
}

func TestSignatureDuplicateAndCorruptPayload(t *testing.T) {
	entries := map[string][]byte{"AppxManifest.xml": []byte(`<Package/>`), "AppxSignature.p7x": []byte("bad"), "APPXSIGNATURE.P7X": []byte("bad")}
	r := scanPackage(testutil.Zip(entries))
	for _, f := range r.Findings {
		if f.ID == "windows.msix.unsigned" {
			t.Fatal("ambiguous signature reported absent")
		}
	}
	b := testutil.Zip(map[string][]byte{"AppxManifest.xml": []byte(`<Package/>`), "app.exe": testutil.PE(testutil.PEOptions{})})
	pos := bytes.LastIndex(b, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint32(b[pos+16:], 0xdeadbeef)
	r = scanPackage(b)
	if !notesContain(r, "checksum") {
		t.Fatal(r.Skipped)
	}
}

func TestManifestPrefixIndependenceAndFindingCap(t *testing.T) {
	a, e := parseAppxManifest([]byte(testutil.AppxManifest), "AppxManifest.xml", "", false)
	if e != nil {
		t.Fatal(e)
	}
	changed := strings.ReplaceAll(testutil.AppxManifest, "rescap:", "alternate:")
	changed = strings.ReplaceAll(changed, "xmlns:rescap=", "xmlns:alternate=")
	b, e := parseAppxManifest([]byte(changed), "AppxManifest.xml", "", false)
	if e != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("prefix changed interpretation", e)
	}
	huge := `<Package><Applications>` + strings.Repeat(`<Application Id="A"/>`, maxManifestFindings+1) + `</Applications></Package>`
	if _, e := parseAppxManifest([]byte(huge), "AppxManifest.xml", "", false); e == nil {
		t.Fatal("finding cap")
	}
	mixed := `<Package><Extensions><Extension Category="windows.service"><Service StartAccount="localService"/></Extension><Extension Category="windows.service"><Service StartAccount="localSystem"/></Extension></Extensions></Package>`
	m, e := parseAppxManifest([]byte(mixed), "AppxManifest.xml", "", false)
	if e != nil {
		t.Fatal(e)
	}
	r := report.Build(target.Result{Findings: m.findings})
	if len(r.Findings) != 1 || r.Findings[0].Severity != model.Sensitive || !strings.Contains(r.Findings[0].Title, "LocalSystem") {
		t.Fatal(r.Findings)
	}
}
