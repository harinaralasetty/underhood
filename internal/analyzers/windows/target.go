package windows

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/target"
)

const maxFolderPE = 200
const maxAnalyzedPE = 20

type PE struct{}
type Folder struct{}

func init()                 { target.Register(PE{}); target.Register(Folder{}) }
func (PE) Kind() string     { return "windows-pe" }
func (Folder) Kind() string { return "windows-folder" }
func (PE) Detect(path string) (bool, string) {
	f, e := inventory.Open(path)
	if e != nil {
		return false, ""
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return false, ""
	}
	return DetectPE(f, st.Size()), ""
}
func (Folder) Detect(path string) (bool, string) {
	if inventory.Safe(path) != nil {
		return false, ""
	}
	st, e := os.Lstat(path)
	if e != nil || !st.IsDir() {
		return false, ""
	}
	if hasManifest(path) {
		return true, ""
	}
	files, _ := folderFiles(path, true)
	return len(files) > 0, ""
}
func hasManifest(root string) bool {
	p := filepath.Join(root, "AppxManifest.xml")
	st, e := os.Lstat(p)
	return e == nil && (st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0)
}
func initial(root, kind string) target.Result {
	home, _ := os.UserHomeDir()
	return target.Result{Target: model.Target{Kind: kind, Path: model.Clean(root, "", home), Name: filepath.Base(root)}, Limits: []string{SignatureNotice, "Imports are heuristics common in legitimate tools and in malware; presence does not establish use.", "No registry, services or scheduled tasks are inspected; external manifests and installer contents are not read."}}
}
func analyzeFile(path, label string, opts model.Options) ([]model.Finding, []model.SkipNote, error) {
	f, e := inventory.Open(path)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, nil, e
	}
	findings, skips := AnalyzePE(f, st.Size(), label, opts)
	return findings, skips, nil
}
func (PE) Analyze(c target.Context) (target.Result, error) {
	r := initial(c.Root, "windows-pe")
	var e error
	r.Findings, r.Skipped, e = analyzeFile(c.Root, "", c.Options)
	for _, f := range r.Findings {
		if len(f.Evidence) == 0 {
			continue
		}
		v := f.Evidence[0].Value
		switch f.ID {
		case "windows.version.ProductName":
			r.Target.Name = v
		case "windows.version.OriginalFilename":
			r.Target.ID = v
		case "windows.version.ProductVersion":
			r.Target.Version = v
		}
	}
	if r.Target.Version == "" {
		for _, f := range r.Findings {
			if f.ID == "windows.version.FileVersion" && len(f.Evidence) > 0 {
				r.Target.Version = f.Evidence[0].Value
				break
			}
		}
	}
	if r.Target.Version == "" {
		for _, f := range r.Findings {
			if f.ID == "windows.version.fixed" && len(f.Evidence) > 0 {
				r.Target.Version = f.Evidence[0].Value
				break
			}
		}
	}
	name := filepath.Base(c.Root)
	for i := range r.Findings {
		for j := range r.Findings[i].Evidence {
			if r.Findings[i].Evidence[j].File == "." {
				r.Findings[i].Evidence[j].File = name
			}
		}
	}
	for i := range r.Skipped {
		if r.Skipped[i].File == "." {
			r.Skipped[i].File = name
		}
	}
	cleanResult(&r, c.Root)
	return r, e
}

type folderFile struct {
	path string
	size int64
	dll  bool
}

// ReadDir is batched so a hostile directory cannot allocate an unbounded listing.
func folderFiles(root string, first bool) ([]folderFile, []model.SkipNote) {
	var files []folderFile
	var notes []model.SkipNote
	visited := 0
	note := func(p, s string) {
		notes = append(notes, model.SkipNote{Analyzer: "WindowsFolder", File: inventory.Relative(root, p), Reason: s, Count: 1})
	}
	var walk func(string, int)
	walk = func(dir string, depth int) {
		if inventory.Safe(dir) != nil {
			note(dir, "symlink not traversed or directory unavailable")
			return
		}
		f, e := os.Open(dir)
		if e != nil {
			note(dir, "directory unavailable")
			return
		}
		defer f.Close()

		// Sort a bounded complete directory before selecting candidates. If it
		// cannot fit, skip it entirely rather than depend on filesystem order.
		remaining := model.MaxFiles - visited
		entries, err := f.ReadDir(remaining + 1)
		if len(entries) > remaining {
			visited = model.MaxFiles
			note(dir, "directory exceeds remaining inventory budget; entire directory skipped for deterministic selection")
			return
		}
		if err != nil && err != io.EOF {
			note(dir, "directory read failed")
			return
		}
		visited += len(entries)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, d := range entries {
			if len(files) >= maxFolderPE || (first && len(files) > 0) {
				return
			}
			p := filepath.Join(dir, d.Name())
			if d.Type()&os.ModeSymlink != 0 {
				note(p, "symlink not traversed")
				continue
			}
			if d.IsDir() {
				if depth < 1 && visited < model.MaxFiles {
					walk(p, depth+1)
				}
				continue
			}
			st, e := d.Info()
			if e != nil || !st.Mode().IsRegular() {
				continue
			}
			f, e := inventory.Open(p)
			if e != nil {
				note(p, "file unavailable")
				continue
			}
			ok := DetectPE(f, st.Size())
			f.Close()
			if ok {
				files = append(files, folderFile{p, st.Size(), strings.EqualFold(filepath.Ext(p), ".dll")})
			}
		}
	}
	walk(root, 0)
	if !first && (visited >= model.MaxFiles || len(files) >= maxFolderPE) {
		note(root, "inventory cap reached (20,000 entries / 200 PE files); inventory is incomplete")
	}
	sort.Slice(files, func(i, j int) bool {
		a, b := files[i], files[j]
		ae, be := strings.EqualFold(filepath.Ext(a.path), ".exe"), strings.EqualFold(filepath.Ext(b.path), ".exe")
		if ae != be {
			return ae
		}
		if a.size != b.size {
			return a.size > b.size
		}
		return a.path < b.path
	})
	return files, notes
}
func (Folder) Analyze(c target.Context) (target.Result, error) {
	r := initial(c.Root, "windows-folder")
	if hasManifest(c.Root) {
		r.Skipped = append(r.Skipped, model.SkipNote{Analyzer: "WindowsFolder", File: "AppxManifest.xml", Reason: "MSIX folder analysis arrives in a later release", Count: 1})
		return r, nil
	}
	files, notes := folderFiles(c.Root, false)
	r.Skipped = notes
	dll := 0
	var uninstallers []string
	for i, f := range files {
		rel := inventory.Relative(c.Root, f.path)
		if f.dll {
			dll++
		}
		base := strings.ToLower(filepath.Base(f.path))
		if base == "unins000.exe" || base == "uninstall.exe" {
			uninstallers = append(uninstallers, rel)
		}
		if i >= maxAnalyzedPE {
			r.Skipped = append(r.Skipped, model.SkipNote{Analyzer: "WindowsFolder", File: rel, Reason: "20 PE analysis cap: listed only: " + rel, Count: 1})
			continue
		}
		findings, skips, e := analyzeFile(f.path, rel, c.Options)
		if e != nil {
			r.Skipped = append(r.Skipped, model.SkipNote{Analyzer: "WindowsFolder", File: rel, Reason: "file unavailable", Count: 1})
			continue
		}
		r.Findings = append(r.Findings, findings...)
		r.Skipped = append(r.Skipped, skips...)
	}
	sort.Strings(uninstallers)
	r.Findings = append(r.Findings, model.Finding{ID: "windows.folder.inventory", Category: "identity", Title: "Windows folder inventory", Detail: "Counts cover detected PE files; installer/uninstaller names do not establish behavior.", Severity: model.Info, Confidence: model.Declared, Evidence: []model.Evidence{{File: ".", Locator: "inventory", Value: fmt.Sprintf("%d PE files; %d .dll files; uninstallers by name: %s", len(files), dll, strings.Join(uninstallers, ", "))}}})
	cleanResult(&r, c.Root)
	capFolderHosts(&r)
	return r, nil
}
func cleanResult(r *target.Result, root string) {
	home, _ := os.UserHomeDir()
	clean := func(s string) string { return model.Clean(s, root, home) }
	r.Target.Name = clean(r.Target.Name)
	r.Target.ID = clean(r.Target.ID)
	r.Target.Version = clean(r.Target.Version)
	for i := range r.Findings {
		f := &r.Findings[i]
		f.ID = clean(f.ID)
		f.Title = clean(f.Title)
		f.Detail = clean(f.Detail)
		for j := range f.Evidence {
			e := &f.Evidence[j]
			e.File = clean(e.File)
			e.Locator = clean(e.Locator)
			e.Value = model.Truncate(clean(e.Value), 200)
		}
	}
	for i := range r.Skipped {
		r.Skipped[i].File = clean(r.Skipped[i].File)
		r.Skipped[i].Reason = clean(r.Skipped[i].Reason)
	}
}

// capFolderHosts applies the shared report-wide host/evidence budget after PE scans.
func capFolderHosts(r *target.Result) {
	hosts := map[string]model.Finding{}
	var other []model.Finding
	for _, f := range r.Findings {
		if !strings.HasPrefix(f.ID, "net.host.") {
			other = append(other, f)
			continue
		}
		if old, ok := hosts[f.ID]; ok {
			old.Evidence = append(old.Evidence, f.Evidence...)
			hosts[f.ID] = old
		} else {
			hosts[f.ID] = f
		}
	}
	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	capped := false
	for i, name := range names {
		if i >= model.MaxHosts {
			capped = true
			break
		}
		f := hosts[name]
		sort.Slice(f.Evidence, func(i, j int) bool {
			a, b := f.Evidence[i], f.Evidence[j]
			if a.File != b.File {
				return a.File < b.File
			}
			if a.Locator != b.Locator {
				return a.Locator < b.Locator
			}
			return a.Value < b.Value
		})
		seen := map[model.Evidence]bool{}
		var ev []model.Evidence
		for _, e := range f.Evidence {
			if seen[e] {
				continue
			}
			seen[e] = true
			if len(ev) >= model.MaxHostEvidence {
				capped = true
				continue
			}
			ev = append(ev, e)
		}
		f.Evidence = ev
		other = append(other, f)
	}
	r.Findings = other
	if capped {
		r.Skipped = append(r.Skipped, model.SkipNote{Analyzer: "WindowsFolder", File: ".", Reason: "report-wide endpoint cap reached (200 hosts / 20 evidence entries per host)", Count: 1})
	}
}
