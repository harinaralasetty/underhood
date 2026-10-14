package windows

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
)

const maxManifestNodes = 10000
const maxManifestFindings = 2048

type appxNode struct {
	name     xml.Name
	attrs    []xml.Attr
	text     string
	children []*appxNode
}

func (n *appxNode) attr(key string) string {
	for _, a := range n.attrs {
		if a.Name.Local == key {
			return a.Value
		}
	}
	return ""
}
func (n *appxNode) child(name string) *appxNode {
	for _, c := range n.children {
		if c.name.Local == name {
			return c
		}
	}
	return nil
}
func (n *appxNode) values() string {
	var a []string
	for _, v := range n.attrs {
		if v.Name.Local != "xmlns" && v.Name.Space != "xmlns" {
			a = append(a, v.Name.Local+"="+v.Value)
		}
	}
	sort.Strings(a)
	if strings.TrimSpace(n.text) != "" {
		a = append(a, strings.TrimSpace(n.text))
	}
	return strings.Join(a, "; ")
}

// Parse a bounded tree without schema/version or prefix assumptions. DTDs and
// external entities are not supported. No partial claims survive invalid XML.
func parseAppxXML(data []byte) (*appxNode, error) {
	if len(data) > model.MaxMetadata {
		return nil, fmt.Errorf("manifest exceeds 16 MiB cap")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	var root *appxNode
	var stack []*appxNode
	nodes := 0
	for {
		tok, e := d.Token()
		if e == io.EOF {
			if root == nil || len(stack) != 0 {
				return nil, fmt.Errorf("incomplete manifest")
			}
			return root, nil
		}
		if e != nil {
			return nil, fmt.Errorf("invalid manifest XML: %w", e)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			nodes++
			if nodes > maxManifestNodes || len(stack) >= 64 || len(x.Attr) > 128 {
				return nil, fmt.Errorf("manifest node/depth/attribute cap exceeded")
			}
			seen := map[string]bool{}
			for _, a := range x.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
					continue
				}
				if seen[a.Name.Local] {
					return nil, fmt.Errorf("ambiguous manifest attribute %s", a.Name.Local)
				}
				seen[a.Name.Local] = true
			}
			n := &appxNode{name: x.Name, attrs: x.Attr}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple manifest roots")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(x)) != "" {
					return nil, fmt.Errorf("text outside manifest root")
				}
				continue
			}
			n := stack[len(stack)-1]
			if len(n.text)+len(x) > 65536 {
				return nil, fmt.Errorf("manifest text cap exceeded")
			}
			n.text += string(x)
		case xml.Directive:
			return nil, fmt.Errorf("manifest directives are unsupported")
		}
	}
}

type appxManifest struct {
	name, publisher, version, display string
	executables                       []string
	packages                          []bundlePackage
	findings                          []model.Finding
}
type bundlePackage struct{ file, kind string }

func parseAppxManifest(data []byte, file, label string, bundle bool) (appxManifest, error) {
	var m appxManifest
	root, err := parseAppxXML(data)
	if err != nil {
		return m, err
	}
	expected := "Package"
	if bundle {
		expected = "Bundle"
	}
	if root.name.Local != expected {
		return m, fmt.Errorf("expected %s manifest root", expected)
	}
	add := func(id, cat, title, detail, locator, value string, sev model.Severity) {
		f := peFinding("windows.msix."+id, cat, title, detail, sev, model.Declared, label, locator, value)
		f.Evidence[0].File = file
		m.findings = append(m.findings, f)
	}
	if n := root.child("Identity"); n != nil {
		m.name, m.publisher, m.version = n.attr("Name"), n.attr("Publisher"), n.attr("Version")
		add("identity", "identity", "Package identity", "Manifest identity declaration.", "Identity", n.values(), model.Info)
	}
	for _, container := range root.children {
		switch container.name.Local {
		case "Properties":
			for _, n := range container.children {
				if n.name.Local == "DisplayName" || n.name.Local == "PublisherDisplayName" {
					if n.name.Local == "DisplayName" {
						m.display = strings.TrimSpace(n.text)
					}
					add("property."+n.name.Local, "identity", n.name.Local, "Manifest property; resource references are not resolved.", "Properties/"+n.name.Local, n.values(), model.Info)
				}
			}
		case "Dependencies":
			for _, n := range container.children {
				if n.name.Local == "TargetDeviceFamily" || n.name.Local == "PackageDependency" {
					add("dependency."+n.name.Local, "identity", "Package dependency", "Declared dependency; installation is not checked.", "Dependencies/"+n.name.Local, n.values(), model.Info)
				}
			}
		case "Capabilities":
			for _, n := range container.children {
				switch n.name.Local {
				case "Capability", "DeviceCapability", "CustomCapability":
				default:
					continue
				}
				name := n.attr("Name")
				if name == "" {
					continue
				}
				rule, known := capabilityRules[name]
				sev, meaning := model.Info, "Unmapped capability (raw declaration)."
				restricted := strings.Contains(strings.ToLower(n.name.Space), "restrictedcapabilities")
				family := "capability."
				if known {
					sev, meaning = rule.severity, rule.meaning
					restricted = restricted || sev == model.Sensitive
				}
				if restricted {
					family = "restricted."
				}
				add(family+name, "capabilities", "Declares capability: "+name, meaning+" Declaration does not establish permission grant or use.", "Capabilities/"+n.name.Local+"/@Name", name, sev)
			}
		case "Packages":
			if bundle {
				for _, n := range container.children {
					if n.name.Local == "Package" {
						m.packages = append(m.packages, bundlePackage{n.attr("FileName"), n.attr("Type")})
						add("bundle.package", "identity", "Bundled package", "Resource packages are listed only; application packages are inspected within caps.", "Packages/Package", n.values(), model.Info)
					}
				}
			}
		}
	}
	var walk func(*appxNode, string, string)
	walk = func(n *appxNode, loc, extension string) {
		if len(m.findings) > maxManifestFindings {
			return
		}
		loc += "/" + n.name.Local
		switch n.name.Local {
		case "Application":
			add("application", "windows-manifest", "Application declaration", "Declared executable, entry point, runtime behavior and trust level.", loc, n.values(), model.Info)
			if exe := n.attr("Executable"); exe != "" {
				m.executables = append(m.executables, exe)
			}
		case "Extension":
			extension = n.attr("Category")
			title, detail, sev := extensionMeaning(extension)
			add("extension."+extension, "windows-manifest", title, detail, loc, n.values(), sev)
			index := len(m.findings) - 1
			var collect func(*appxNode, string)
			collect = func(child *appxNode, where string) {
				where += "/" + child.name.Local
				if v := child.values(); v != "" {
					m.findings[index].Evidence = append(m.findings[index].Evidence, model.Evidence{File: file, Locator: where, Value: v})
				}
				if extension == "windows.service" && strings.EqualFold(child.attr("StartAccount"), "localSystem") {
					m.findings[index].Severity = model.Sensitive
					m.findings[index].Title = "Declares a LocalSystem service"
					m.findings[index].Detail = "The declared service runs as LocalSystem; installation and execution are not assessed."
				}
				for _, c := range child.children {
					collect(c, where)
				}
			}
			for _, c := range n.children {
				collect(c, loc)
			}
			return
		case "Rule":
			if strings.Contains(loc, "/ApplicationContentUriRules/") {
				add("uri-rule", "network", "Declares content URI rule", "A manifest URL rule, not observed network traffic.", loc, n.values(), model.Notable)
			}
		}
		for _, c := range n.children {
			walk(c, loc, extension)
		}
	}
	walk(root, "", "")
	if len(m.findings) > maxManifestFindings {
		return appxManifest{}, fmt.Errorf("manifest finding cap exceeded")
	}
	// Repeated extension categories share an ID; keep their displayed title
	// consistent with the strongest declaration when report.Build merges them.
	strongest := map[string]model.Finding{}
	for _, f := range m.findings {
		if f.Severity == model.Sensitive {
			strongest[f.ID] = f
		}
	}
	for i, f := range m.findings {
		if high, ok := strongest[f.ID]; ok {
			m.findings[i].Title = high.Title
			m.findings[i].Detail = high.Detail
		}
	}
	return m, nil
}
func extensionMeaning(category string) (string, string, model.Severity) {
	title, detail, sev := "Declares extension: "+category, "Raw extension declaration; activation is not observed.", model.Info
	switch category {
	case "windows.protocol":
		title = "Registers a URL protocol"
	case "windows.fileTypeAssociation":
		title = "Registers file types"
	case "windows.startupTask":
		title = "Declares a startup task"
		detail = "Declares a task that can run at sign-in; Enabled is the manifest setting, not current user state."
		sev = model.Notable
	case "windows.appExecutionAlias":
		title = "Registers command aliases"
	case "windows.service":
		title = "Declares a packaged service"
	case "windows.firewallRules":
		title = "Declares firewall rules"
		detail = "Declared directions, protocols and ports; effective firewall configuration is not inspected."
		sev = model.Notable
	case "windows.appUriHandler":
		title = "Registers web URI hosts"
	case "windows.backgroundTasks":
		title = "Declares background tasks"
	case "windows.comServer":
		title = "Registers a COM server"
	case "windows.shareTarget":
		title = "Registers a share target"
	case "windows.appService":
		title = "Declares an app service"
	case "windows.fullTrustProcess":
		title = "Declares a full-trust process"
		detail = "Declares a process outside the app sandbox with the user's privileges."
		sev = model.Sensitive
	}
	return title, detail, sev
}
