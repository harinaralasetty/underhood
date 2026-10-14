package windows

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
)

// importRules is the authoritative heuristic table; wildcard suffixes match API variants.
var importRules = []struct {
	id, title     string
	dlls, symbols []string
	severity      model.Severity
}{
	{"network", "Network APIs", []string{"ws2_32", "wsock32", "wininet", "winhttp", "urlmon", "httpapi", "dnsapi"}, nil, model.Notable},
	{"crypto", "Cryptographic APIs", []string{"bcrypt", "ncrypt", "crypt32"}, nil, model.Info},
	{"process", "Process and memory manipulation APIs", nil, []string{"OpenProcess", "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext"}, model.Notable},
	{"input", "Keyboard and input APIs", nil, []string{"SetWindowsHookEx*", "GetAsyncKeyState", "RegisterRawInputDevices"}, model.Notable},
	{"services", "Service APIs", nil, []string{"CreateService*", "StartServiceCtrlDispatcher*"}, model.Notable},
	{"privilege", "Privilege APIs", nil, []string{"AdjustTokenPrivileges", "LookupPrivilegeValue*"}, model.Notable},
	{"clipboard", "Clipboard APIs", nil, []string{"GetClipboardData"}, model.Notable},
	{"debugger", "Debugger detection APIs", nil, []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent"}, model.Notable},
	{"dynamic", "Dynamic loading APIs", nil, []string{"LoadLibrary*", "GetProcAddress"}, model.Info},
}

type peImport struct{ dll, symbol string }

func importCString(r io.ReaderAt, size int64, p *pe.File, rva uint32) (string, error) {
	b := make([]byte, 0, 256)
	for i := uint32(0); i < 512; i++ {
		if uint64(rva)+uint64(i) > 0xffffffff {
			return "", fmt.Errorf("import RVA overflow")
		}
		off, e := peOffset(p, size, rva+i, 1)
		if e != nil {
			return "", e
		}
		var c [1]byte
		if _, e = r.ReadAt(c[:], off); e != nil {
			return "", e
		}
		if c[0] == 0 {
			return string(b), nil
		}
		if c[0] < 32 || c[0] > 126 {
			return "", fmt.Errorf("non-ASCII import name")
		}
		b = append(b, c[0])
	}
	return "", fmt.Errorf("import name cap reached")
}
func readImports(r io.ReaderAt, size int64, p *pe.File) ([]peImport, error) {
	d := peDirectory(p, 1)
	if d.VirtualAddress == 0 || d.Size == 0 {
		return nil, nil
	}
	var imports []peImport
	width := uint32(4)
	if _, ok := p.OptionalHeader.(*pe.OptionalHeader64); ok {
		width = 8
	}
	for i := uint32(0); i < 256; i++ {
		if uint64(i)*20+20 > uint64(d.Size) || uint64(d.VirtualAddress)+uint64(i)*20 > 0xffffffff {
			return imports, fmt.Errorf("import descriptor bounds exceeded")
		}
		off, e := peOffset(p, size, d.VirtualAddress+i*20, 20)
		if e != nil {
			return imports, e
		}
		var b [20]byte
		if _, e = r.ReadAt(b[:], off); e != nil {
			return imports, e
		}
		if b == [20]byte{} {
			return imports, nil
		}
		dll, e := importCString(r, size, p, binary.LittleEndian.Uint32(b[12:]))
		if e != nil {
			return imports, e
		}
		imports = append(imports, peImport{dll: dll})
		thunk := binary.LittleEndian.Uint32(b[:])
		if thunk == 0 {
			thunk = binary.LittleEndian.Uint32(b[16:])
		}
		for j := uint32(0); ; j++ {
			if len(imports) >= 8192 {
				return imports, fmt.Errorf("import count cap of 8192 reached")
			}
			if uint64(thunk)+uint64(j)*uint64(width) > 0xffffffff {
				return imports, fmt.Errorf("import thunk overflow")
			}
			off, e := peOffset(p, size, thunk+j*width, width)
			if e != nil {
				return imports, e
			}
			var v [8]byte
			if _, e = r.ReadAt(v[:width], off); e != nil {
				return imports, e
			}
			n := binary.LittleEndian.Uint64(v[:])
			if n == 0 {
				break
			}
			if n&(uint64(1)<<(width*8-1)) != 0 {
				imports = append(imports, peImport{dll, fmt.Sprintf("ordinal %d", n&65535)})
				continue
			}
			if n > 0xfffffffd {
				return imports, fmt.Errorf("invalid import name RVA")
			}
			name, e := importCString(r, size, p, uint32(n)+2)
			if e != nil {
				return imports, e
			}
			imports = append(imports, peImport{dll, name})
		}
	}
	return imports, fmt.Errorf("import descriptor cap of 256 reached")
}
func analyzeImports(r io.ReaderAt, size int64, p *pe.File, label string) ([]model.Finding, []model.SkipNote) {
	imports, e := readImports(r, size, p)
	var skips []model.SkipNote
	if e != nil {
		skips = append(skips, peNote(label, "imports: "+e.Error()))
	}
	if d := peDirectory(p, 13); d.VirtualAddress != 0 && d.Size != 0 {
		skips = append(skips, peNote(label, "Delay-load imports are not analysed"))
	}
	var f []model.Finding
	libs := map[string]bool{}
	for _, v := range imports {
		libs[v.dll] = true
	}
	names := make([]string, 0, len(libs))
	for name := range libs {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 0 {
		f = append(f, peFinding("windows.imports.libraries", "imports", "Imported libraries", "Static import declarations; dynamically loaded libraries may be absent.", model.Info, model.Declared, label, "ImportDirectory", strings.Join(names, ", ")))
	}
	for _, rule := range importRules {
		matched := map[string]bool{}
		for _, v := range imports {
			dll := strings.TrimSuffix(strings.ToLower(v.dll), ".dll")
			for _, d := range rule.dlls {
				if dll == d {
					if v.symbol != "" {
						matched[v.dll+":"+v.symbol] = true
					} else {
						matched[v.dll] = true
					}
				}
			}
			for _, s := range rule.symbols {
				if strings.EqualFold(s, v.symbol) || (strings.HasSuffix(s, "*") && strings.HasPrefix(strings.ToLower(v.symbol), strings.ToLower(strings.TrimSuffix(s, "*")))) {
					matched[v.dll+":"+v.symbol] = true
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		values := make([]string, 0, len(matched))
		for v := range matched {
			values = append(values, v)
		}
		sort.Strings(values)
		detail := "These APIs are common in legitimate tools and in malware; presence does not establish use."
		if rule.id == "dynamic" {
			detail += " Dynamic resolution means static imports under-report available APIs."
		}
		finding := peFinding("windows.imports."+rule.id, "imports", rule.title, detail, rule.severity, model.Heuristic, label, "ImportDirectory", "")
		finding.Evidence = nil
		for _, v := range values[:min(10, len(values))] {
			file := label
			if file == "" {
				file = "."
			}
			finding.Evidence = append(finding.Evidence, model.Evidence{File: file, Locator: "ImportDirectory", Value: v})
		}
		if len(values) > 10 {
			skips = append(skips, peNote(label, fmt.Sprintf("%s import evidence capped at 10 of %d matches", rule.id, len(values))))
		}
		f = append(f, finding)
	}
	return f, skips
}
