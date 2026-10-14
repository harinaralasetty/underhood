package windows

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/harinaralasetty/underhood/internal/model"
)

const resourceLimit = 4 << 20

func resourceFinding(label, path, id, title, value, category string, severity model.Severity) model.Finding {
	if label != "" {
		id += "@" + label
	}
	file := label
	if file == "" {
		file = "."
	}
	return model.Finding{ID: id, Category: category, Title: title, Detail: value, Severity: severity, Confidence: model.Declared, Evidence: []model.Evidence{{File: file, Locator: path, Value: value}}}
}

func resourceOffset(p *pe.File, rva uint32, n uint32, size int64) (int64, error) {
	for _, s := range p.Sections {
		if uint64(rva) < uint64(s.VirtualAddress) {
			continue
		}
		delta := uint64(rva) - uint64(s.VirtualAddress)
		if delta+uint64(n) > uint64(s.Size) {
			continue
		}
		off := uint64(s.Offset) + delta
		if off+uint64(n) <= uint64(size) {
			return int64(off), nil
		}
	}
	return 0, fmt.Errorf("resource RVA outside file-backed sections")
}

func analyzeResources(r io.ReaderAt, size int64, p *pe.File, label string) ([]model.Finding, []model.SkipNote) {
	var dir pe.DataDirectory
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if h.NumberOfRvaAndSizes > 2 {
			dir = h.DataDirectory[2]
		}
	case *pe.OptionalHeader64:
		if h.NumberOfRvaAndSizes > 2 {
			dir = h.DataDirectory[2]
		}
	}
	if dir.VirtualAddress == 0 && dir.Size == 0 {
		return nil, nil
	}
	var findings []model.Finding
	var skips []model.SkipNote
	skip := func(err error) {
		file := label
		if file == "" {
			file = "."
		}
		skips = append(skips, model.SkipNote{Analyzer: "windows-resources", File: file, Reason: err.Error(), Count: 1})
	}
	if dir.Size < 16 || dir.Size > resourceLimit {
		skip(fmt.Errorf("resource directory size invalid or exceeds 4 MiB cap"))
		return findings, skips
	}
	off, err := resourceOffset(p, dir.VirtualAddress, dir.Size, size)
	if err != nil {
		skip(err)
		return findings, skips
	}
	b := make([]byte, int(dir.Size))
	if _, err = r.ReadAt(b, off); err != nil {
		skip(fmt.Errorf("truncated resource directory"))
		return findings, skips
	}
	totalBytes := uint64(0)
	err = walkResources(b, func(kind uint32, path string, rva, n uint32) error {
		if kind != 16 && kind != 24 {
			return nil
		}
		if n == 0 || n > resourceLimit {
			return fmt.Errorf("%s: resource size invalid or exceeds 4 MiB cap", path)
		}
		totalBytes += uint64(n)
		if totalBytes > model.MaxMetadata {
			return fmt.Errorf("resource payloads exceed 16 MiB aggregate cap")
		}
		pos, e := resourceOffset(p, rva, n, size)
		if e != nil {
			skip(fmt.Errorf("%s: %v", path, e))
			return nil
		}
		data := make([]byte, int(n))
		if _, e = r.ReadAt(data, pos); e != nil {
			skip(fmt.Errorf("%s: truncated resource", path))
			return nil
		}
		var fs []model.Finding
		if kind == 16 {
			fs, e = decodeVersion(data, label, path)
		} else {
			fs, e = parsePEManifest(data, label, path)
		}
		findings = append(findings, fs...)
		if e != nil {
			skip(fmt.Errorf("%s: %v", path, e))
		}
		return nil
	})
	if err != nil {
		skip(err)
	}
	return findings, skips
}

func walkResources(b []byte, visit func(uint32, string, uint32, uint32) error) error {
	entries := 0
	var walk func(uint32, int, uint32, string) error
	walk = func(off uint32, depth int, kind uint32, path string) error {
		if depth > 2 || uint64(off)+16 > uint64(len(b)) {
			return fmt.Errorf("malformed resource directory depth or offset")
		}
		n := int(binary.LittleEndian.Uint16(b[off+12:])) + int(binary.LittleEndian.Uint16(b[off+14:]))
		entries += n
		if entries > 4096 || uint64(off)+16+uint64(n)*8 > uint64(len(b)) {
			return fmt.Errorf("resource directory entry cap or bounds exceeded")
		}
		for i := 0; i < n; i++ {
			x := int(off) + 16 + i*8
			name := binary.LittleEndian.Uint32(b[x:])
			dest := binary.LittleEndian.Uint32(b[x+4:])
			part := strconv.FormatUint(uint64(name), 10)
			if name&0x80000000 != 0 {
				at := name & 0x7fffffff
				if uint64(at)+2 > uint64(len(b)) {
					return fmt.Errorf("invalid resource name")
				}
				l := uint32(binary.LittleEndian.Uint16(b[at:]))
				if l > 512 || uint64(at)+2+uint64(l)*2 > uint64(len(b)) {
					return fmt.Errorf("invalid resource name bounds")
				}
				part = resourceUTF16(b[at+2 : at+2+l*2])
			}
			k := kind
			if depth == 0 {
				k = name
				if k == 16 {
					part = "RT_VERSION"
				}
				if k == 24 {
					part = "RT_MANIFEST"
				}
			}
			next := path + "/" + part
			if dest&0x80000000 != 0 {
				if depth == 2 {
					return fmt.Errorf("resource nesting exceeds three levels")
				}
				if e := walk(dest&0x7fffffff, depth+1, k, next); e != nil {
					return e
				}
			} else {
				if depth != 2 || uint64(dest)+16 > uint64(len(b)) {
					return fmt.Errorf("invalid resource data entry")
				}
				if e := visit(k, next, binary.LittleEndian.Uint32(b[dest:]), binary.LittleEndian.Uint32(b[dest+4:])); e != nil {
					return e
				}
			}
		}
		return nil
	}
	return walk(0, 0, 0, ".rsrc")
}

func resourceUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}
func resourceAlign(n int) int { return (n + 3) &^ 3 }

func decodeVersion(b []byte, label, path string) ([]model.Finding, error) {
	var out []model.Finding
	allowed := map[string]bool{"CompanyName": true, "ProductName": true, "FileDescription": true, "FileVersion": true, "ProductVersion": true, "OriginalFilename": true, "LegalCopyright": true, "InternalName": true}
	count := 0
	var block func(int, int, int, string) (int, error)
	block = func(start, end, depth int, parent string) (int, error) {
		count++
		if count > 512 || depth > 4 || start+6 > end {
			return 0, fmt.Errorf("malformed VERSIONINFO block")
		}
		length := int(binary.LittleEndian.Uint16(b[start:]))
		vlen := int(binary.LittleEndian.Uint16(b[start+2:]))
		typ := binary.LittleEndian.Uint16(b[start+4:])
		limit := start + length
		if length < 6 || limit > end {
			return 0, fmt.Errorf("invalid VERSIONINFO length")
		}
		pos := start + 6
		keyStart := pos
		for pos+2 <= limit && binary.LittleEndian.Uint16(b[pos:]) != 0 {
			pos += 2
		}
		if pos+2 > limit {
			return 0, fmt.Errorf("unterminated VERSIONINFO key")
		}
		key := resourceUTF16(b[keyStart:pos])
		pos = resourceAlign(pos + 2)
		bytes := vlen
		if typ == 1 {
			bytes *= 2
		}
		if pos+bytes > limit {
			return 0, fmt.Errorf("invalid VERSIONINFO value length")
		}
		if depth == 0 && key != "VS_VERSION_INFO" {
			return 0, fmt.Errorf("invalid VERSIONINFO root")
		}
		if depth == 0 && bytes > 0 {
			if bytes < 52 || binary.LittleEndian.Uint32(b[pos:]) != 0xfeef04bd {
				return 0, fmt.Errorf("invalid fixed file info")
			}
			ms := binary.LittleEndian.Uint32(b[pos+8:])
			ls := binary.LittleEndian.Uint32(b[pos+12:])
			value := fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&65535, ls>>16, ls&65535)
			out = append(out, resourceFinding(label, path+"/FixedFileVersion", "windows.version.fixed", "Fixed file version", value, "identity", model.Info))
			productMS := binary.LittleEndian.Uint32(b[pos+16:])
			productLS := binary.LittleEndian.Uint32(b[pos+20:])
			fixed := fmt.Sprintf("Product version %d.%d.%d.%d; flags mask 0x%x; flags 0x%x; OS 0x%x; type 0x%x; subtype 0x%x; date 0x%x%08x", productMS>>16, productMS&65535, productLS>>16, productLS&65535, binary.LittleEndian.Uint32(b[pos+24:]), binary.LittleEndian.Uint32(b[pos+28:]), binary.LittleEndian.Uint32(b[pos+32:]), binary.LittleEndian.Uint32(b[pos+36:]), binary.LittleEndian.Uint32(b[pos+40:]), binary.LittleEndian.Uint32(b[pos+44:]), binary.LittleEndian.Uint32(b[pos+48:]))
			out = append(out, resourceFinding(label, path+"/VS_FIXEDFILEINFO", "windows.version.fixedInfo", "Fixed version metadata", fixed, "identity", model.Info))
		}
		if depth == 3 && strings.HasPrefix(parent, "VS_VERSION_INFO/StringFileInfo/") && allowed[key] && typ == 1 {
			out = append(out, resourceFinding(label, path+"/"+key, "windows.version."+key, key, resourceUTF16(b[pos:pos+bytes]), "identity", model.Info))
		}
		pos = resourceAlign(pos + bytes)
		for pos+6 <= limit {
			if binary.LittleEndian.Uint16(b[pos:]) == 0 {
				break
			}
			next, e := block(pos, limit, depth+1, parentKey(parent, key))
			if e != nil {
				return 0, e
			}
			pos = resourceAlign(next)
		}
		return limit, nil
	}
	_, err := block(0, len(b), 0, "")
	return out, err
}
func parentKey(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "/" + key
}
