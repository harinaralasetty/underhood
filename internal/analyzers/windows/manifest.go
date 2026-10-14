package windows

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
)

var supportedWindows = map[string]string{
	"{e2011457-1546-43c5-a5fe-008deee3d3f0}": "Windows Vista",
	"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}": "Windows 7",
	"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}": "Windows 8",
	"{1f676c76-80e1-4239-95bb-83d0f6d0da78}": "Windows 8.1",
	"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}": "Windows 10/11",
}

func parsePEManifest(data []byte, label, path string) ([]model.Finding, error) {
	if len(data) > resourceLimit {
		return nil, fmt.Errorf("manifest exceeds 4 MiB cap")
	}
	// Windows resources can hold UTF-16LE XML, including a UTF-16 declaration.
	if len(data) >= 2 && ((data[0] == 0xff && data[1] == 0xfe) || (data[0] == '<' && data[1] == 0)) {
		if data[0] == 0xff {
			data = data[2:]
		}
		if len(data)%2 != 0 {
			return nil, fmt.Errorf("odd UTF-16 manifest size")
		}
		data = []byte(resourceUTF16(data))
	}
	data = bytes.TrimRight(data, "\x00")
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-16") || strings.EqualFold(charset, "utf-16le") {
			return r, nil
		}
		return nil, fmt.Errorf("unsupported manifest charset")
	}
	var out []model.Finding
	type frame struct {
		name string
		text strings.Builder
	}
	var stack []*frame
	count := 0
	roots := 0
	dependencyDepth := 0
	add := func(key, title, value string, severity model.Severity) {
		if value != "" {
			out = append(out, resourceFinding(label, path+"/"+key, "windows.manifest."+key, title, value, "windows-manifest", severity))
		}
	}
	for {
		t, e := d.Token()
		if e == io.EOF {
			if roots != 1 || len(stack) != 0 {
				return nil, fmt.Errorf("manifest must contain one complete XML root")
			}
			return out, nil
		}
		if e != nil {
			return nil, fmt.Errorf("malformed manifest XML: %v", e)
		}
		if len(out) >= 512 {
			return nil, fmt.Errorf("manifest finding cap exceeded")
		}
		count++
		if count > 50000 {
			return nil, fmt.Errorf("manifest token cap exceeded")
		}
		switch x := t.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
			}
			if len(stack) >= 64 {
				return nil, fmt.Errorf("manifest nesting cap exceeded")
			}
			stack = append(stack, &frame{name: x.Name.Local})
			attr := func(name string) string {
				for _, a := range x.Attr {
					if a.Name.Local == name {
						return a.Value
					}
				}
				return ""
			}
			switch x.Name.Local {
			case "requestedExecutionLevel":
				level := attr("level")
				sev := model.Info
				if level == "requireAdministrator" {
					sev = model.Sensitive
				} else if level == "highestAvailable" {
					sev = model.Notable
				}
				add("requestedExecutionLevel", "Requested execution level", level, sev)
				if v := attr("uiAccess"); v != "" {
					sev = model.Info
					if strings.EqualFold(v, "true") {
						sev = model.Sensitive
					}
					add("uiAccess", "UI access", v, sev)
				}
			case "supportedOS":
				id := attr("Id")
				v := supportedWindows[strings.ToLower(id)]
				if v == "" {
					v = id
				} else {
					v += " (" + id + ")"
				}
				add("supportedOS", "Supported Windows version", v, model.Info)
			case "dependentAssembly":
				dependencyDepth = len(stack)
			case "assemblyIdentity":
				if dependencyDepth > 0 {
					var parts []string
					for _, a := range x.Attr {
						parts = append(parts, a.Name.Local+"="+a.Value)
					}
					add("dependentAssembly", "Assembly dependency", strings.Join(parts, ", "), model.Info)
				}
			}
		case xml.CharData:
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				if f.text.Len()+len(x) > 65536 {
					return nil, fmt.Errorf("manifest text cap exceeded")
				}
				f.text.Write(x)
			} else if strings.TrimSpace(string(x)) != "" {
				return nil, fmt.Errorf("text outside manifest root")
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("unbalanced manifest")
			}
			f := stack[len(stack)-1]
			v := strings.TrimSpace(f.text.String())
			sev := model.Info
			switch f.name {
			case "autoElevate":
				if strings.EqualFold(v, "true") {
					sev = model.Sensitive
				}
				add(f.name, "Automatic elevation", v, sev)
			case "disableWindowFiltering":
				add(f.name, "Window filtering disabled", v, model.Info)
			case "longPathAware":
				add(f.name, "Long path awareness", v, model.Info)
			case "dpiAware", "dpiAwareness":
				add(f.name, "DPI awareness", v, model.Info)
			}
			if dependencyDepth == len(stack) {
				dependencyDepth = 0
			}
			stack = stack[:len(stack)-1]
		}
	}
}
