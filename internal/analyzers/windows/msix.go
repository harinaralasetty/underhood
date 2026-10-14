package windows

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/target"
)

const maxZipEntry = 256 << 20
const maxPackageBytes = 512 << 20
const maxBundleApps = 4

type MSIX struct{}

func init()               { target.Register(MSIX{}) }
func (MSIX) Kind() string { return "windows-msix" }

// Validate the central directory before archive/zip can allocate its file list.
// EOCD search is bounded to the ZIP maximum comment size. ZIP64 offsets are
// accepted, but split archives and oversized directories are not.
func packageZip(r io.ReaderAt, size int64) (*zip.Reader, error) {
	if size < 22 {
		return nil, fmt.Errorf("truncated zip")
	}
	n := int64(65557)
	if size < n {
		n = size
	}
	tail := make([]byte, int(n))
	if _, e := r.ReadAt(tail, size-n); e != nil {
		return nil, e
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if string(tail[i:i+4]) == "PK\x05\x06" && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("zip end record missing")
	}
	directoryEnd := size - n + int64(end)
	b := tail[end:]
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	u64 := binary.LittleEndian.Uint64
	if u16(b[4:]) != 0 || u16(b[6:]) != 0 {
		return nil, fmt.Errorf("split zip unsupported")
	}
	count, dirSize, off := uint64(u16(b[10:])), uint64(u32(b[12:])), uint64(u32(b[16:]))
	if u16(b[8:]) != u16(b[10:]) {
		return nil, fmt.Errorf("split zip entry counts")
	}
	if count == 65535 || dirSize == 0xffffffff || off == 0xffffffff {
		pos := size - n + int64(end) - 20
		var loc [20]byte
		if pos < 0 {
			return nil, fmt.Errorf("missing ZIP64 locator")
		}
		if _, e := r.ReadAt(loc[:], pos); e != nil {
			return nil, e
		}
		if string(loc[:4]) != "PK\x06\x07" || u32(loc[4:]) != 0 || u32(loc[16:]) != 1 || u64(loc[8:]) > uint64(pos) {
			return nil, fmt.Errorf("invalid ZIP64 locator")
		}
		directoryEnd = int64(u64(loc[8:]))
		var z [56]byte
		if _, e := r.ReadAt(z[:], int64(u64(loc[8:]))); e != nil {
			return nil, e
		}
		if string(z[:4]) != "PK\x06\x06" || u64(z[4:]) < 44 || u32(z[16:]) != 0 || u32(z[20:]) != 0 || u64(z[24:]) != u64(z[32:]) {
			return nil, fmt.Errorf("invalid ZIP64 directory")
		}
		count, dirSize, off = u64(z[32:]), u64(z[40:]), u64(z[48:])
	}
	if count > model.MaxFiles || dirSize > model.MaxMetadata || off > uint64(size) || dirSize > uint64(size)-off {
		return nil, fmt.Errorf("zip central directory exceeds bounds (20,000 entries / 16 MiB)")
	}
	if off+dirSize != uint64(directoryEnd) {
		return nil, fmt.Errorf("zip central directory boundary mismatch")
	}
	directory := make([]byte, int(dirSize))
	if _, e := r.ReadAt(directory, int64(off)); e != nil {
		return nil, e
	}
	actual := uint64(0)
	for len(directory) > 0 {
		if len(directory) < 46 || string(directory[:4]) != "PK\x01\x02" {
			return nil, fmt.Errorf("invalid central directory")
		}
		step := 46 + int(u16(directory[28:])) + int(u16(directory[30:])) + int(u16(directory[32:]))
		actual++
		if step > len(directory) || actual > model.MaxFiles {
			return nil, fmt.Errorf("zip entry count/length cap exceeded")
		}
		directory = directory[step:]
	}
	if actual != count {
		return nil, fmt.Errorf("zip entry count mismatch")
	}
	z, e := zip.NewReader(r, size)
	if e != nil {
		return nil, e
	}
	return z, nil
}
func (MSIX) Detect(p string) (bool, string) {
	f, e := inventory.Open(p)
	if e != nil {
		return false, ""
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return false, ""
	}
	var magic [4]byte
	if _, e = f.ReadAt(magic[:], 0); e != nil || string(magic[:]) != "PK\x03\x04" {
		return false, ""
	}
	z, e := packageZip(f, st.Size())
	if e != nil {
		return false, "MSIX: " + e.Error()
	}
	for _, f := range z.File {
		if f.Name == "AppxManifest.xml" || f.Name == "AppxBundleManifest.xml" || f.Name == "AppxMetadata/AppxBundleManifest.xml" {
			return true, ""
		}
	}
	return false, ""
}
func packagePath(s string) (string, error) {
	s = strings.ReplaceAll(s, "\\", "/")
	if s == "" || strings.HasPrefix(s, "/") || strings.ContainsAny(s, ":\x00") {
		return "", fmt.Errorf("unsafe package path")
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == "." || part == "" {
			return "", fmt.Errorf("unsafe package path")
		}
	}
	return s, nil
}
func scoped(label, name string) string {
	if label == "" {
		return name
	}
	return label + "/" + name
}
func msixNote(file, reason string) model.SkipNote {
	return model.SkipNote{Analyzer: "Windows MSIX", File: file, Reason: reason, Count: 1}
}

type packageScan struct {
	result    *target.Result
	opts      model.Options
	remaining int64
	peCount   int
}

func (s *packageScan) note(file, reason string) {
	s.result.Skipped = append(s.result.Skipped, msixNote(file, reason))
}
func (s *packageScan) read(f *zip.File, label string, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) || f.CompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("entry exceeds %d MiB read cap", limit>>20)
	}
	if s.remaining <= 0 || f.UncompressedSize64 > uint64(s.remaining) {
		return nil, fmt.Errorf("512 MiB total expanded-read budget exhausted")
	}
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	// Charge the actual bounded read even on CRC/size failures.
	if s.remaining < limit {
		limit = s.remaining
	}
	data, e := io.ReadAll(io.LimitReader(r, limit+1))
	s.remaining -= int64(len(data))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("expanded entry exceeds read cap")
	}
	if e != nil {
		return nil, e
	}
	return data, nil
}
func (s *packageScan) archive(r io.ReaderAt, size int64, label string, nested bool) {
	z, e := packageZip(r, size)
	if e != nil {
		s.note(label, e.Error())
		return
	}
	files := map[string]*zip.File{}
	duplicates := map[string]bool{}
	signaturePresent := false
	for _, f := range z.File {
		if strings.EqualFold(f.Name, "AppxSignature.p7x") {
			signaturePresent = true
		}
		name, e := packagePath(strings.TrimSuffix(f.Name, "/"))
		if e != nil || strings.Contains(f.Name, "\\") {
			s.note(scoped(label, f.Name), "unsafe zip name skipped; no extraction is performed")
			continue
		}
		if !f.Mode().IsRegular() && !f.Mode().IsDir() {
			s.note(scoped(label, name), "non-regular zip entry skipped")
			continue
		}
		key := strings.ToLower(name)
		if _, ok := files[key]; ok {
			duplicates[key] = true
		}
		files[key] = f
	}
	for key := range duplicates {
		delete(files, key)
		s.note(scoped(label, key), "duplicate case-insensitive zip path skipped")
	}
	manifestName := "AppxManifest.xml"
	bundle := false
	for _, name := range []string{"AppxMetadata/AppxBundleManifest.xml", "AppxBundleManifest.xml"} {
		if files[strings.ToLower(name)] != nil {
			manifestName = name
			bundle = true
			break
		}
	}
	if bundle && nested {
		s.note(label, "nested bundle skipped: one bundle-to-package level only")
		return
	}
	mf := files[strings.ToLower(manifestName)]
	if mf == nil {
		s.note(scoped(label, manifestName), "package manifest missing or ambiguous")
		return
	}
	data, e := s.read(mf, label, model.MaxMetadata)
	var m appxManifest
	if e == nil {
		m, e = parseAppxManifest(data, scoped(label, mf.Name), label, bundle)
	}
	if e != nil {
		s.note(scoped(label, mf.Name), e.Error())
	} else {
		s.result.Findings = append(s.result.Findings, m.findings...)
		if label == "" {
			applyPackageIdentity(s.result, m)
		}
	}
	if signaturePresent && files["appxsignature.p7x"] == nil {
		f := peFinding("windows.msix.signature-unparsable", "signing", "Package signature present but ambiguous", SignatureNotice, model.Notable, model.Declared, label, "AppxSignature.p7x", "signature path is ambiguous or non-regular")
		f.Evidence[0].File = scoped(label, "AppxSignature.p7x")
		s.result.Findings = append(s.result.Findings, f)
	} else {
		s.signature(files["appxsignature.p7x"], label, m.publisher, scoped(label, mf.Name))
	}
	top := map[string]int{}
	var executables []string
	for _, f := range files {
		if f.FileInfo().IsDir() {
			continue
		}
		key := strings.SplitN(f.Name, "/", 2)[0]
		if !strings.Contains(f.Name, "/") {
			key = "(root files)"
		}
		top[key]++
		if strings.EqualFold(path.Ext(f.Name), ".exe") {
			executables = append(executables, f.Name)
		}
	}
	sort.Strings(executables)
	layout := peFinding("windows.msix.contents", "identity", "Package contents", "Counts describe safe, unambiguous entries; executable names do not establish execution.", model.Info, model.Declared, label, "zip entries", fmt.Sprintf("%d entries; %d executable files", len(z.File), len(executables)))
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		layout.Evidence = append(layout.Evidence, model.Evidence{File: scoped(label, k), Locator: "entry count", Value: fmt.Sprint(top[k])})
	}
	for _, name := range executables {
		layout.Evidence = append(layout.Evidence, model.Evidence{File: scoped(label, name), Locator: "executable", Value: name})
	}
	s.result.Findings = append(s.result.Findings, layout)
	if bundle {
		sort.Slice(m.packages, func(i, j int) bool { return m.packages[i].file < m.packages[j].file })
		count := 0
		seen := map[string]bool{}
		for _, p := range m.packages {
			if p.kind != "application" {
				continue
			}
			name, e := packagePath(p.file)
			if e != nil {
				s.note(scoped(label, p.file), e.Error())
				continue
			}
			key := strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true
			if count >= maxBundleApps {
				s.note(scoped(label, name), "4 application-package analysis cap reached")
				continue
			}
			count++
			f := files[key]
			if f == nil {
				s.note(scoped(label, name), "declared application package missing")
				continue
			}
			b, e := s.read(f, label, maxZipEntry)
			if e != nil {
				s.note(scoped(label, name), e.Error())
				continue
			}
			s.archive(bytes.NewReader(b), int64(len(b)), scoped(label, f.Name), true)
		}
		return
	}
	// Declared applications first, then other EXEs, each sorted and deduplicated.
	sort.Strings(m.executables)
	names := append(m.executables, executables...)
	seen := map[string]bool{}
	for _, raw := range names {
		name, e := packagePath(raw)
		if e != nil {
			s.note(scoped(label, raw), e.Error())
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		f := files[key]
		if f == nil {
			s.note(scoped(label, name), "declared executable missing or ambiguous")
			continue
		}
		if s.peCount >= maxAnalyzedPE {
			s.note(scoped(label, name), "20 PE analysis cap reached")
			continue
		}
		s.peCount++
		b, e := s.read(f, label, maxZipEntry)
		if e != nil {
			s.note(scoped(label, name), e.Error())
			continue
		}
		fs, ns := AnalyzePE(bytes.NewReader(b), int64(len(b)), scoped(label, f.Name), s.opts)
		s.result.Findings = append(s.result.Findings, fs...)
		s.result.Skipped = append(s.result.Skipped, ns...)
	}
}
func applyPackageIdentity(r *target.Result, m appxManifest) {
	r.Target.ID = m.name
	r.Target.Version = m.version
	if m.display != "" {
		r.Target.Name = m.display
	} else if m.name != "" {
		r.Target.Name = m.name
	}
}
func (MSIX) Analyze(c target.Context) (target.Result, error) {
	r := initial(c.Root, "windows-msix")
	f, e := inventory.Open(c.Root)
	if e != nil {
		return r, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return r, e
	}
	s := packageScan{result: &r, opts: c.Options, remaining: maxPackageBytes}
	s.archive(f, st.Size(), "", false)
	cleanResult(&r, c.Root)
	capFolderHosts(&r)
	return r, nil
}
func analyzeAppxFolder(c target.Context) (target.Result, error) {
	r := initial(c.Root, "windows-folder")
	data, e := inventory.ReadMetadata(filepath.Join(c.Root, "AppxManifest.xml"))
	if e != nil {
		r.Skipped = append(r.Skipped, msixNote("AppxManifest.xml", "manifest unavailable: unsafe path, read error or metadata cap"))
		return r, nil
	}
	m, e := parseAppxManifest(data, "AppxManifest.xml", "", false)
	if e != nil {
		r.Skipped = append(r.Skipped, msixNote("AppxManifest.xml", e.Error()))
		return r, nil
	}
	applyPackageIdentity(&r, m)
	r.Findings = append(r.Findings, m.findings...)
	r.Limits = append(r.Limits, "Unpacked-folder package signatures are not assessed; only the manifest and declared application executables are read.")
	sort.Strings(m.executables)
	seen := map[string]bool{}
	count := 0
	for _, raw := range m.executables {
		name, e := packagePath(raw)
		if e != nil {
			r.Skipped = append(r.Skipped, msixNote(raw, e.Error()))
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if count >= maxAnalyzedPE {
			r.Skipped = append(r.Skipped, msixNote(name, "20 PE analysis cap reached"))
			continue
		}
		count++
		fs, ns, e := analyzeFile(filepath.Join(c.Root, filepath.FromSlash(name)), name, c.Options)
		if e != nil {
			r.Skipped = append(r.Skipped, msixNote(name, "declared executable unavailable; symlinks are not followed"))
			continue
		}
		r.Findings = append(r.Findings, fs...)
		r.Skipped = append(r.Skipped, ns...)
	}
	cleanResult(&r, c.Root)
	capFolderHosts(&r)
	return r, nil
}
