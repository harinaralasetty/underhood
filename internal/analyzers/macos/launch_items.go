package macos

import (
	"fmt"
	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/plist"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

var launchLocations = []string{"Contents/Library/LaunchAgents", "Contents/Library/LaunchDaemons", "Contents/Library/LoginItems", "Contents/Library/LaunchServices", "Contents/XPCServices"}
var launchKeys = []string{"Label", "Program", "ProgramArguments", "RunAtLoad", "KeepAlive", "StartInterval", "MachServices", "Sockets"}

func referencesPath(value, path string) bool {
	start := 0
	for start < len(value) {
		i := strings.Index(value[start:], path)
		if i < 0 {
			return false
		}
		i += start
		j := i + len(path)
		before := i == 0 || strings.ContainsRune("=\"' \t\n", rune(value[i-1]))
		after := j == len(value) || strings.ContainsRune("/\"' \t\n", rune(value[j]))
		if before && after {
			return true
		}
		start = j
	}
	return false
}
func launchPlist(c *context, p string, match bool) {
	b, e := inventory.ReadMetadata(p)
	var d map[string]any
	if e == nil {
		d, e = plist.Decode(b)
	}
	if e != nil {
		c.note("LaunchItems", p, e.Error())
		return
	}
	ev := []model.Evidence{}
	if match {
		id := str(c.mainInfo()["CFBundleIdentifier"])
		if id != "" && strings.HasPrefix(str(d["Label"]), id) {
			ev = append(ev, c.ev(p, "Label", d["Label"]))
		}
		associated := d["AssociatedBundleIdentifiers"]
		if id != "" {
			if str(associated) == id {
				ev = append(ev, c.ev(p, "AssociatedBundleIdentifiers", associated))
			}
			for _, v := range array(associated) {
				if str(v) == id {
					ev = append(ev, c.ev(p, "AssociatedBundleIdentifiers", associated))
					break
				}
			}
		}
		var find func(any, string)
		find = func(v any, loc string) {
			switch x := v.(type) {
			case string:
				if referencesPath(x, c.root) {
					ev = append(ev, c.ev(p, loc, x))
				}
			case []any:
				for i, v := range x {
					find(v, fmt.Sprintf("%s[%d]", loc, i))
				}
			case map[string]any:
				for _, k := range keys(x) {
					l := k
					if loc != "" {
						l = loc + "." + k
					}
					find(x[k], l)
				}
			}
		}
		find(d, "")
		if len(ev) == 0 {
			return
		}
	}
	details := []string{}
	for _, k := range launchKeys {
		if v, ok := d[k]; ok {
			ev = append(ev, c.ev(p, k, v))
			details = append(details, k+"="+model.Text(v))
		}
	}
	if len(ev) == 0 {
		ev = append(ev, c.ev(p, "plist", d))
	}
	name := str(d["Label"])
	if name == "" {
		name = filepath.Base(p)
	}
	c.add("launch.plist@"+c.rel(p), "launchItems", "Launch job: "+name, "Launch job declaration; presence does not establish that the job is loaded. "+strings.Join(details, "; "), model.Notable, model.Declared, ev...)
}
func launchItems(c *context) error {
	entries := append(append([]string{}, c.inv.Files...), c.inv.Directories...)
	sort.Strings(entries)
	for _, b := range c.inv.Bundles {
		for _, loc := range launchLocations {
			dir := filepath.Join(b, filepath.FromSlash(loc))
			for _, child := range entries {
				if filepath.Dir(child) != dir {
					continue
				}
				if filepath.Ext(child) == ".plist" {
					launchPlist(c, child, false)
				} else {
					c.add("launch.embedded@"+c.rel(child), "launchItems", "Embedded "+filepath.Base(dir)+": "+filepath.Base(child), "Found in the bundle's "+loc+" directory; presence does not prove registration or execution.", model.Notable, model.Heuristic, c.ev(child, "bundle directory entry", filepath.Base(child)))
				}
			}
		}
	}
	for _, r := range c.records {
		for _, k := range []string{"SMPrivilegedExecutables", "SMAuthorizedClients"} {
			if v, ok := r.info[k]; ok {
				c.add("launch."+k+c.suffix(r.path), "launchItems", k, "Privileged helper authorization declaration: "+model.Text(v), model.Sensitive, model.Declared, c.ev(r.infoPath, k, v))
			}
		}
	}
	if runtime.GOOS != "darwin" {
		c.note("LaunchItems", c.root, "host launch-job scan unavailable on non-macOS hosts")
		return nil
	}
	dirs := []string{filepath.Join(c.home, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"}
	sort.Strings(dirs)
	count := 0
	for _, dir := range dirs {
		if e := inventory.Safe(dir); e != nil {
			c.note("LaunchItems", dir, e.Error())
			continue
		}
		f, e := os.Open(dir)
		if e != nil {
			c.note("LaunchItems", dir, e.Error())
			continue
		}
		entries, e := f.ReadDir(model.MaxFiles - count + 1)
		f.Close()
		if e != nil && len(entries) == 0 {
			c.note("LaunchItems", dir, e.Error())
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, ent := range entries {
			if count >= model.MaxFiles {
				c.note("LaunchItems", dir, "system launch entry cap of 20,000 reached")
				return nil
			}
			count++
			p := filepath.Join(dir, ent.Name())
			if filepath.Ext(p) != ".plist" {
				continue
			}
			if ent.Type()&os.ModeSymlink != 0 {
				c.note("LaunchItems", p, "system launch symlink not traversed")
				continue
			}
			info, e := ent.Info()
			if e == nil && info.Mode().IsRegular() {
				launchPlist(c, p, true)
			}
		}
	}
	return nil
}
