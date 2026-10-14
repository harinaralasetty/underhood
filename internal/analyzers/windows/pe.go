// Package windows inspects Windows artifacts without executing their contents.
package windows

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/harinaralasetty/underhood/internal/model"
)

const maxPESections = 96

// DetectPE reads only the DOS, COFF and optional-header prefixes. EFI is excluded.
func DetectPE(r io.ReaderAt, size int64) bool {
	_, err := peHeader(r, size)
	return err == nil
}

func peHeader(r io.ReaderAt, size int64) (int64, error) {
	var dos [64]byte
	if size < 96 {
		return 0, fmt.Errorf("truncated DOS header")
	}
	if _, e := r.ReadAt(dos[:], 0); e != nil {
		return 0, e
	}
	if string(dos[:2]) != "MZ" {
		return 0, fmt.Errorf("missing MZ signature")
	}
	off := int64(binary.LittleEndian.Uint32(dos[60:]))
	var h [94]byte
	if off < 64 || off > size-int64(len(h)) {
		return 0, fmt.Errorf("PE header outside file")
	}
	if _, e := r.ReadAt(h[:], off); e != nil {
		return 0, e
	}
	if string(h[:4]) != "PE\x00\x00" {
		return 0, fmt.Errorf("missing PE signature")
	}
	sections := int64(binary.LittleEndian.Uint16(h[6:]))
	optionalSize := int64(binary.LittleEndian.Uint16(h[20:]))
	if sections == 0 || sections > maxPESections || optionalSize < 96 || optionalSize > 4096 || off+24+optionalSize+sections*40 > size {
		return 0, fmt.Errorf("PE header/section bounds exceeded")
	}
	magic := binary.LittleEndian.Uint16(h[24:])
	if (magic != 0x10b && magic != 0x20b) || (magic == 0x20b && optionalSize < 112) {
		return 0, fmt.Errorf("unsupported optional header")
	}
	sub := binary.LittleEndian.Uint16(h[92:])
	if sub >= 10 && sub <= 13 {
		return 0, fmt.Errorf("EFI images are excluded")
	}
	dll := binary.LittleEndian.Uint16(h[22:])&0x2000 != 0
	if sub != 1 && sub != 2 && sub != 3 && sub != 7 && sub != 9 && sub != 14 && sub != 16 && !dll {
		return 0, fmt.Errorf("not a Windows subsystem")
	}
	return off, nil
}

func openPE(r io.ReaderAt, size int64) (*pe.File, error) {
	off, e := peHeader(r, size)
	if e != nil {
		return nil, e
	}
	var h [24]byte
	if _, e = r.ReadAt(h[:], off); e != nil {
		return nil, e
	}
	count := int64(binary.LittleEndian.Uint16(h[6:]))
	opt := int64(binary.LittleEndian.Uint16(h[20:]))
	if count > maxPESections || opt > 4096 || off+24+opt+count*40 > size {
		return nil, fmt.Errorf("section/header bounds exceeded")
	}
	ptr := int64(binary.LittleEndian.Uint32(h[12:]))
	symbols := int64(binary.LittleEndian.Uint32(h[16:]))
	if symbols > 65536 {
		return nil, fmt.Errorf("COFF symbol count cap exceeded")
	}
	if ptr != 0 {
		end := ptr + symbols*18
		if end > size-4 || end > 0xffffffff {
			return nil, fmt.Errorf("COFF symbol table outside file")
		}
		var b [4]byte
		if _, e = r.ReadAt(b[:], end); e != nil {
			return nil, e
		}
		n := int64(binary.LittleEndian.Uint32(b[:]))
		if n > model.MaxMetadata || end+n > size {
			return nil, fmt.Errorf("COFF string table bounds exceeded")
		}
	}
	for i := int64(0); i < count; i++ {
		var s [40]byte
		if _, e = r.ReadAt(s[:], off+24+opt+i*40); e != nil {
			return nil, e
		}
		raw := int64(binary.LittleEndian.Uint32(s[20:]))
		n := int64(binary.LittleEndian.Uint32(s[16:]))
		if raw != 0 && raw+n > size {
			return nil, fmt.Errorf("section data outside file")
		}
		reloc := int64(binary.LittleEndian.Uint32(s[24:]))
		rn := int64(binary.LittleEndian.Uint16(s[32:]))
		if rn > 4096 || (rn > 0 && reloc+rn*10 > size) {
			return nil, fmt.Errorf("relocation bounds exceeded")
		}
	}
	// debug/pe rejects some otherwise inspectable machine values (including
	// legacy ARM). Parse the common layout with UNKNOWN then retain the raw value.
	machine := binary.LittleEndian.Uint16(h[4:])
	p, err := pe.NewFile(machineNeutralReader{io.NewSectionReader(r, 0, size), off + 4})
	if err == nil {
		p.Machine = machine
	}
	return p, err
}

type machineNeutralReader struct {
	io.ReaderAt
	machineOffset int64
}

func (r machineNeutralReader) ReadAt(b []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(b, off)
	for i := 0; i < n; i++ {
		if off+int64(i) == r.machineOffset || off+int64(i) == r.machineOffset+1 {
			b[i] = 0
		}
	}
	return n, err
}

func peDirectory(p *pe.File, index int) pe.DataDirectory {
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if index < int(h.NumberOfRvaAndSizes) && index < len(h.DataDirectory) {
			return h.DataDirectory[index]
		}
	case *pe.OptionalHeader64:
		if index < int(h.NumberOfRvaAndSizes) && index < len(h.DataDirectory) {
			return h.DataDirectory[index]
		}
	}
	return pe.DataDirectory{}
}
func peOffset(p *pe.File, size int64, rva, n uint32) (int64, error) {
	for _, s := range p.Sections {
		if rva >= s.VirtualAddress {
			delta := uint64(rva) - uint64(s.VirtualAddress)
			if delta+uint64(n) <= uint64(s.Size) && s.Offset != 0 {
				off := uint64(s.Offset) + delta
				if off+uint64(n) <= uint64(size) {
					return int64(off), nil
				}
			}
		}
	}
	return 0, fmt.Errorf("RVA %#x is outside section data", rva)
}
func peFinding(id, category, title, detail string, severity model.Severity, confidence model.Confidence, label, locator, value string) model.Finding {
	if label != "" {
		id += "@" + label
	}
	if label == "" {
		label = "."
	}
	return model.Finding{ID: id, Category: category, Title: title, Detail: detail, Severity: severity, Confidence: confidence, Evidence: []model.Evidence{{File: label, Locator: locator, Value: value}}}
}
func peNote(label, reason string) model.SkipNote {
	if label == "" {
		label = "."
	}
	return model.SkipNote{Analyzer: "Windows PE", File: label, Reason: reason, Count: 1}
}

// AnalyzePE inspects a bounded ReaderAt, including future in-memory package entries.
func AnalyzePE(r io.ReaderAt, size int64, label string, opts model.Options) ([]model.Finding, []model.SkipNote) {
	p, e := openPE(r, size)
	if e != nil {
		return nil, []model.SkipNote{peNote(label, e.Error())}
	}
	defer p.Close()
	var f []model.Finding
	var skips []model.SkipNote
	add := func(id, cat, title, detail, locator, value string, sev model.Severity) {
		f = append(f, peFinding("windows."+id, cat, title, detail, sev, model.Declared, label, locator, value))
	}
	machine := map[uint16]string{0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c0: "ARM", 0x1c4: "ARM"}[p.Machine]
	if machine == "" {
		machine = fmt.Sprintf("other (%#x)", p.Machine)
	}
	add("identity.machine", "identity", "Machine", machine, "COFF.Machine", machine, model.Info)
	kind := "EXE"
	if p.Characteristics&0x2000 != 0 {
		kind = "DLL"
	}
	add("identity.type", "identity", "Image type", kind, "COFF.Characteristics", kind, model.Info)
	add("identity.timestamp", "identity", "Linker timestamp", "The COFF timestamp can be forged or zeroed for reproducible builds.", "COFF.TimeDateStamp", fmt.Sprintf("%d (%s)", p.TimeDateStamp, time.Unix(int64(p.TimeDateStamp), 0).UTC().Format(time.RFC3339)), model.Info)
	var sub, flags, osmajor, osminor, submajor, subminor uint16
	var image uint32
	var lm, ln uint8
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sub, flags, osmajor, osminor, submajor, subminor, image, lm, ln = h.Subsystem, h.DllCharacteristics, h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion, h.MajorSubsystemVersion, h.MinorSubsystemVersion, h.SizeOfImage, h.MajorLinkerVersion, h.MinorLinkerVersion
	case *pe.OptionalHeader64:
		sub, flags, osmajor, osminor, submajor, subminor, image, lm, ln = h.Subsystem, h.DllCharacteristics, h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion, h.MajorSubsystemVersion, h.MinorSubsystemVersion, h.SizeOfImage, h.MajorLinkerVersion, h.MinorLinkerVersion
	}
	subs := map[uint16]string{1: "native", 2: "GUI", 3: "console", 7: "POSIX console", 9: "Windows CE GUI", 14: "Xbox", 16: "Windows boot application"}[sub]
	if subs == "" {
		subs = fmt.Sprintf("other (%d)", sub)
	}
	add("identity.subsystem", "identity", "Subsystem", subs, "OptionalHeader.Subsystem", subs, model.Info)
	add("identity.versions", "identity", "Image versions", "Declared linker, OS and subsystem versions.", "OptionalHeader", fmt.Sprintf("linker %d.%d; OS %d.%d; subsystem %d.%d; image size %d", lm, ln, osmajor, osminor, submajor, subminor, image), model.Info)
	if d := peDirectory(p, 14); d.VirtualAddress != 0 && d.Size != 0 {
		add("identity.managed", "identity", "Managed assembly", "CLR runtime header declared; .NET metadata is not decompiled.", "DataDirectory[14]", fmt.Sprintf("RVA %#x, size %d", d.VirtualAddress, d.Size), model.Info)
	}
	for _, flag := range []struct {
		id, title string
		bit       uint16
		missing   bool
	}{{"aslr", "ASLR", 0x40, true}, {"highEntropyVA", "High-entropy VA", 0x20, false}, {"forceIntegrity", "Force integrity", 0x80, false}, {"nx", "NX compatibility", 0x100, true}, {"noSEH", "No SEH", 0x400, false}, {"appContainer", "AppContainer", 0x1000, false}, {"cfg", "Control Flow Guard", 0x4000, true}, {"terminalServerAware", "Terminal-server aware", 0x8000, false}} {
		enabled := flags&flag.bit != 0
		sev := model.Info
		title := flag.title
		if !enabled && flag.missing {
			sev = model.Notable
			title += " not declared"
		}
		add("hardening."+flag.id, "hardening", title, "Header declaration only; runtime enforcement is not assessed.", "OptionalHeader.DllCharacteristics", fmt.Sprintf("%t", enabled), sev)
	}
	for i, s := range p.Sections {
		sev := model.Info
		title := "Section " + s.Name
		if s.Characteristics&0xa0000000 == 0xa0000000 {
			sev = model.Notable
			title += " is executable and writable"
		}
		add(fmt.Sprintf("section.%d", i), "sections", title, "Section flags and sizes are static declarations.", fmt.Sprintf("Sections[%d]", i), fmt.Sprintf("%s; raw %d; virtual %d; flags %#x", s.Name, s.Size, s.VirtualSize, s.Characteristics), sev)
	}
	for _, analyze := range []func(io.ReaderAt, int64, *pe.File, string) ([]model.Finding, []model.SkipNote){analyzeResources, analyzeSignatures, analyzeImports} {
		a, b := analyze(r, size, p, label)
		f = append(f, a...)
		skips = append(skips, b...)
	}
	if opts.BinaryStrings {
		a, b := analyzeStrings(r, size, label, opts)
		f = append(f, a...)
		skips = append(skips, b...)
	}
	return f, skips
}
