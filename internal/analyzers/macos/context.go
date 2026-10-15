// Package macos implements the macos-app target with in-process analyzers.
package macos

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/plist"
	"github.com/harinaralasetty/underhood/internal/target"
)

// App is the portable macOS bundle target.
type App struct{}

func init() { target.Register(App{}) }

// Kind names the target registry entry.
func (App) Kind() string { return "macos-app" }

// Detect requires a regular, non-symlink Contents/Info.plist in an .app directory.
func (App) Detect(path string) (bool, string) {
	if !strings.EqualFold(filepath.Ext(path), ".app") {
		return false, "expected an .app directory"
	}
	if e := inventory.Safe(path); e != nil {
		return false, e.Error()
	}
	st, e := os.Lstat(path)
	if e != nil || !st.IsDir() {
		return false, "app directory unavailable"
	}
	p := filepath.Join(path, "Contents", "Info.plist")
	if e := inventory.Safe(p); e != nil {
		return false, e.Error()
	}
	st, e = os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() {
		return false, "Contents/Info.plist must be a regular file"
	}
	return true, ""
}

type record struct {
	path, infoPath string
	info           map[string]any
}
type signingTarget struct {
	path, binary string
	slices       []macho.Slice
}
type context struct {
	root, home string
	options    model.Options
	inv        inventory.Inventory
	records    []record
	signing    []signingTarget
	parsed     map[string][]macho.Slice
	result     target.Result
}

// Analyzer is a named, isolated analysis step; custom lists support failure testing.
type Analyzer struct {
	Name string
	Run  func(*context) error
}

// Analyze inventories once, then runs independent analyzers without failing the run.
func (App) Analyze(input target.Context) (target.Result, error) { return analyze(input, nil) }
func analyze(input target.Context, analyzers []Analyzer) (target.Result, error) {
	home, _ := os.UserHomeDir()
	c := &context{root: input.Root, home: home, options: input.Options, parsed: map[string][]macho.Slice{}}
	c.inv = inventory.Walk(c.root, model.MaxFiles)
	c.result.Skipped = append(c.result.Skipped, c.inv.Notes...)
	files := map[string]bool{}
	for _, f := range c.inv.Files {
		files[f] = true
	}
	for _, b := range c.inv.Bundles {
		p := ""
		for _, rel := range []string{"Contents/Info.plist", "Resources/Info.plist", "Info.plist"} {
			candidate := filepath.Join(b, filepath.FromSlash(rel))
			if files[candidate] {
				p = candidate
				break
			}
		}
		if p == "" {
			for _, f := range c.inv.Files {
				if strings.HasPrefix(f, filepath.Join(b, "Versions")+string(filepath.Separator)) && filepath.Base(f) == "Info.plist" {
					p = f
					break
				}
			}
		}
		if p != "" {
			data, e := inventory.ReadMetadata(p)
			var info map[string]any
			if e == nil {
				info, e = plist.Decode(data)
			}
			if e != nil {
				c.note("BundleInfo", p, e.Error())
			} else {
				c.records = append(c.records, record{b, p, info})
			}
		}
	}
	for _, b := range c.inv.Binaries {
		s, e := macho.Parse(b)
		if e != nil {
			c.note("MachO", b, e.Error())
			for i := range s {
				s[i].Error = e.Error()
			}
		}
		c.parsed[b] = s
		for _, slice := range s {
			if slice.Error != "" && e == nil {
				c.note("MachO", b, slice.Architecture+": "+slice.Error)
			}
			if slice.Signature != nil {
				for _, n := range slice.Signature.Notes {
					c.note("CodeSigning", b, slice.Architecture+": "+n)
				}
			}
		}
	}
	represented := map[string]bool{}
	for _, b := range c.inv.Bundles {
		exe := ""
		for _, r := range c.records {
			if r.path == b {
				exe = c.executable(r)
				break
			}
		}
		originalExe := exe
		if exe == "" { // Versioned frameworks have their actual binary below Versions, not at their symlink entry.
			for _, f := range c.inv.Binaries {
				if strings.HasPrefix(f, b+string(filepath.Separator)) && filepath.Base(f) == strings.TrimSuffix(filepath.Base(b), filepath.Ext(b)) {
					exe = f
					break
				}
			}
		}
		if exe != "" {
			if originalExe != "" {
				represented[exe] = true
			}
			c.signing = append(c.signing, signingTarget{b, exe, c.parsed[exe]})
		} else {
			c.signing = append(c.signing, signingTarget{path: b})
		}
	}
	for _, b := range c.inv.Binaries {
		if !represented[b] {
			c.signing = append(c.signing, signingTarget{b, b, c.parsed[b]})
		}
	}
	sort.Slice(c.signing, func(i, j int) bool { return c.signing[i].path < c.signing[j].path })
	info := c.mainInfo()
	name := str(info["CFBundleDisplayName"])
	if name == "" {
		name = str(info["CFBundleName"])
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(c.root), filepath.Ext(c.root))
	}
	value := func(k string) string {
		s := str(info[k])
		if s == "" {
			return "unknown"
		}
		return s
	}
	c.result.Target = model.Target{Kind: "macos-app", Path: c.clean(c.root), Name: name, ID: value("CFBundleIdentifier"), Version: value("CFBundleShortVersionString"), Build: value("CFBundleVersion")}
	c.result.Target.Path = model.Clean(c.root, "", home)
	if analyzers == nil {
		analyzers = []Analyzer{{"BundleInfo", bundleInfo}, {"CodeSigning", codeSigning}, {"Entitlements", entitlements}, {"Permissions", permissions}, {"URLSchemes", urlSchemes}, {"LaunchItems", launchItems}, {"Automation", automation}, {"Network", network}}
	}
	for _, a := range analyzers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.note(a.Name, c.root, fmt.Sprintf("analyzer failed: %v", r))
				}
			}()
			if e := a.Run(c); e != nil {
				c.note(a.Name, c.root, e.Error())
			}
		}()
	}
	return c.result, nil
}
func (c *context) mainInfo() map[string]any {
	for _, r := range c.records {
		if r.path == c.root {
			return r.info
		}
	}
	return map[string]any{}
}
func (c *context) executable(r record) string {
	name := str(r.info["CFBundleExecutable"])
	if name == "" || name == ".." || strings.ContainsAny(name, "/\\") {
		return ""
	}
	for _, p := range []string{filepath.Join(r.path, "Contents", "MacOS", name), filepath.Join(r.path, name)} {
		if _, ok := c.parsed[p]; ok {
			return p
		}
	}
	return ""
}
func (c *context) clean(s string) string { return model.Clean(s, c.root, c.home) }
func (c *context) rel(s string) string {
	// Paths inside the target stay bundle-relative even when the target itself lives under the home directory.
	if r := inventory.Relative(c.root, s); r != ".." && !strings.HasPrefix(r, "../") && !filepath.IsAbs(r) {
		return r
	}
	if c.home != "" && (s == c.home || strings.HasPrefix(s, c.home+string(filepath.Separator))) {
		return "~" + filepath.ToSlash(strings.TrimPrefix(s, c.home))
	}
	return inventory.Relative(c.root, s)
}
func (c *context) suffix(s string) string {
	if s == c.root || s == filepath.Join(c.root, "Contents", "Info.plist") {
		return ""
	}
	return "@" + c.rel(s)
}
func (c *context) ev(file, key string, v any) model.Evidence {
	return model.Evidence{File: c.rel(file), Locator: c.clean(key), Value: model.Truncate(c.clean(model.Text(v)), 200)}
}
func (c *context) note(a, p, reason string) {
	c.result.Skipped = append(c.result.Skipped, model.SkipNote{Analyzer: a, File: c.rel(p), Reason: c.clean(reason), Count: 1})
}
func (c *context) add(id, category, title, detail string, sev model.Severity, confidence model.Confidence, evidence ...model.Evidence) {
	c.result.Findings = append(c.result.Findings, model.Finding{ID: c.clean(id), Category: category, Title: c.clean(title), Detail: c.clean(detail), Severity: sev, Confidence: confidence, Evidence: evidence})
}
func str(v any) string          { s, _ := v.(string); return s }
func dict(v any) map[string]any { d, _ := v.(map[string]any); return d }
func array(v any) []any         { a, _ := v.([]any); return a }
func keys(d map[string]any) []string {
	k := make([]string, 0, len(d))
	for s := range d {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}
func sliceLocator(s macho.Slice) string {
	return fmt.Sprintf("Mach-O %s slice at byte %d", s.Architecture, s.Offset)
}
func eachEnt(c *context, fn func(signingTarget, macho.Slice, map[string]any)) {
	for _, t := range c.signing {
		for _, s := range t.slices {
			if s.Error != "" || s.Signature == nil || s.Signature.EntitlementError != "" {
				continue
			}
			fn(t, s, s.Signature.Entitlements)
		}
	}
}
