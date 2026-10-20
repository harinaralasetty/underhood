// Package cli parses interspersed arguments and enforces read-only output boundaries.
package cli

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	_ "github.com/harinaralasetty/underhood/internal/analyzers/macos"
	_ "github.com/harinaralasetty/underhood/internal/analyzers/windows"
	"github.com/harinaralasetty/underhood/internal/diff"
	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/report"
	"github.com/harinaralasetty/underhood/internal/target"
)

// Usage describes command arguments and exit statuses.
const Usage = `Underhood — static, offline app inspection
Usage: underhood <path> [--format md|json|both] [--output <path>]
       [--max-binary-mb <n>] [--no-binary-strings] [--full] [--version] [--help]
       underhood diff OLD NEW [--format markdown|json|both] [--output <path>] [--full]
Supported kinds: macos-app, windows-pe, windows-folder, windows-msix.
Flags may appear before or after the path; -- ends option parsing.
--format both requires --output <basepath> (writes .md and .json).
--max-binary-mb is a positive MiB limit per binary (default 300).
--output atomically replaces regular files outside target/system directories (mode 0600).
Directories, symlinks and other non-regular outputs are refused.
Exit codes: 0 report produced; 1 usage/output error; 2 invalid target.
`

// Options is the parsed CLI configuration.
type Options struct {
	Path, Format, Output string
	OldPath              string
	Diff                 bool
	Scan                 model.Options
	Full, Help, Version  bool
}

// Parse accepts interspersed flags and one target, or OLD and NEW after diff.
func Parse(args []string) (Options, error) {
	o := Options{Format: "md", Scan: model.Options{MaxBinaryMB: model.DefaultBinaryMB, BinaryStrings: true}}
	if len(args) > 0 && args[0] == "diff" {
		o.Diff = true
		args = args[1:]
	}
	seen := map[string]bool{}
	positional := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !positional && a == "--" {
			positional = true
			continue
		}
		if !positional && strings.HasPrefix(a, "-") {
			if seen[a] {
				return o, fmt.Errorf("duplicate option: %s", a)
			}
			seen[a] = true
			switch a {
			case "--format", "--output", "--max-binary-mb":
				if i+1 >= len(args) {
					return o, fmt.Errorf("missing value for %s", a)
				}
				i++
				v := args[i]
				switch a {
				case "--format":
					o.Format = v
				case "--output":
					if v == "" {
						return o, fmt.Errorf("empty --output")
					}
					o.Output = v
				case "--max-binary-mb":
					n, e := strconv.ParseInt(v, 10, 64)
					if e != nil || n <= 0 || n > (1<<63-1)>>20 {
						return o, fmt.Errorf("invalid --max-binary-mb")
					}
					o.Scan.MaxBinaryMB = n
				}
			case "--no-binary-strings":
				o.Scan.BinaryStrings = false
			case "--full":
				o.Full = true
			case "--help":
				o.Help = true
			case "--version":
				o.Version = true
			default:
				return o, fmt.Errorf("unknown option: %s", a)
			}
		} else {
			if o.Diff && o.OldPath == "" {
				o.OldPath = a
				continue
			}
			if o.Path != "" {
				return o, fmt.Errorf("unexpected argument: %s", a)
			}
			o.Path = a
		}
	}
	if o.Format == "markdown" {
		o.Format = "md"
	}
	if o.Format != "md" && o.Format != "json" && o.Format != "both" {
		return o, fmt.Errorf("--format must be markdown (md), json, or both")
	}
	if !o.Help && !o.Version && o.Path == "" {
		return o, fmt.Errorf("missing target path")
	}
	if o.Format == "both" && o.Output == "" {
		return o, fmt.Errorf("--format both requires --output")
	}
	return o, nil
}
func inside(path, root string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		path = strings.ToLower(path)
		root = strings.ToLower(root)
	}
	r, e := filepath.Rel(root, path)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
func systemPath(p string) bool {
	if runtime.GOOS == "windows" {
		for _, v := range []string{os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if v != "" && inside(strings.ToLower(p), strings.ToLower(v)) {
				return true
			}
		}
		return false
	}
	for _, tmp := range []string{"/tmp", "/private/tmp", os.TempDir()} {
		resolved, e := filepath.EvalSymlinks(tmp)
		if e == nil && inside(p, resolved) {
			return false
		}
	}
	for _, root := range []string{"/System", "/Library", "/Applications", "/usr", "/bin", "/sbin", "/etc", "/private", "/dev", "/opt", "/var", "/cores", "/Network", "/proc", "/sys", "/boot"} {
		if inside(p, root) {
			return true
		}
	}
	return filepath.Dir(p) == string(filepath.Separator)
}

// sameAncestor also catches filesystem aliases with different lexical paths.
func sameAncestor(path, root string) bool {
	targetInfo, e := os.Stat(root)
	if e != nil {
		return false
	}
	for {
		info, e := os.Stat(path)
		if e == nil && os.SameFile(targetInfo, info) {
			return true
		}
		next := filepath.Dir(path)
		if next == path {
			return false
		}
		path = next
	}
}

func destination(name, root string) (string, error) {
	p, e := filepath.Abs(name)
	if e != nil {
		return "", e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(p))
	if e != nil {
		return "", fmt.Errorf("output parent directory must exist: %w", e)
	}
	p = filepath.Join(parent, filepath.Base(p))
	if inside(p, root) || sameAncestor(parent, root) || systemPath(p) {
		return "", fmt.Errorf("output must be outside target and system directories")
	}
	st, e := os.Lstat(p)
	if e == nil {
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("output must be a regular file, not a symlink")
		}
		return p, nil
	}
	if !os.IsNotExist(e) {
		return "", e
	}
	return p, nil
}

// Run executes the command and returns its documented exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	fail := func(code int, e error) int { fmt.Fprintln(stderr, "underhood:", e); return code }
	o, e := Parse(args)
	if e != nil {
		return fail(1, e)
	}
	if o.Help {
		fmt.Fprint(stdout, Usage)
		return 0
	}
	if o.Version {
		fmt.Fprintln(stdout, "underhood", model.Version)
		return 0
	}
	var old model.Report
	if o.Diff {
		result, err := target.Analyze(o.OldPath, o.Scan)
		if err != nil {
			return fail(2, fmt.Errorf("OLD: %w", err))
		}
		old = report.Build(result)
	}
	r, e := target.Analyze(o.Path, o.Scan)
	if e != nil {
		if o.Diff {
			e = fmt.Errorf("NEW: %w", e)
		}
		return fail(2, e)
	}
	rep := report.Build(r)
	var md, js bytes.Buffer
	if o.Diff {
		comparison := diff.Compare(old, rep)
		if o.Format != "json" {
			e = diff.Markdown(&md, comparison, o.Full)
		}
		if e == nil && o.Format != "md" {
			e = diff.JSON(&js, comparison)
		}
	} else {
		if o.Format != "json" {
			e = report.Markdown(&md, rep, o.Full)
		}
		if e == nil && o.Format != "md" {
			e = report.JSON(&js, rep)
		}
	}
	if e != nil {
		return fail(1, e)
	}
	if o.Output == "" {
		data := md.Bytes()
		if o.Format == "json" {
			data = js.Bytes()
		}
		_, e = stdout.Write(data)
		if e != nil {
			return fail(1, e)
		}
		return 0
	}
	roots := []string{}
	inputs := []string{o.Path}
	if o.Diff {
		inputs = append(inputs, o.OldPath)
	}
	for _, input := range inputs {
		root, err := filepath.EvalSymlinks(input)
		if err != nil {
			return fail(1, err)
		}
		root, err = filepath.Abs(root)
		if err != nil {
			return fail(1, err)
		}
		roots = append(roots, root)
	}
	names := []string{o.Output}
	data := [][]byte{md.Bytes()}
	if o.Format == "json" {
		data[0] = js.Bytes()
	}
	if o.Format == "both" {
		names = []string{o.Output + ".md", o.Output + ".json"}
		data = [][]byte{md.Bytes(), js.Bytes()}
	}
	paths := []string{}
	for _, name := range names {
		var p string
		for _, root := range roots {
			var err error
			p, err = destination(name, root)
			if err != nil {
				return fail(1, err)
			}
		}
		paths = append(paths, p)
	}
	if e := writeOutputs(paths, data, atomicWrite); e != nil {
		return fail(1, e)
	}
	return 0
}

// writeOutputs only rolls back destinations created by this run. Replacements
// remain intact if a later write fails; restoring old contents is not atomic.
func writeOutputs(paths []string, data [][]byte, write func(string, []byte) error) error {
	existed := make([]bool, len(paths))
	for i, p := range paths {
		st, err := os.Lstat(p)
		if err == nil {
			if !st.Mode().IsRegular() {
				return fmt.Errorf("output must be a regular file, not a symlink")
			}
			existed[i] = true
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for i, p := range paths {
		if err := write(p, data[i]); err != nil {
			for j := 0; j < i; j++ {
				if !existed[j] {
					_ = os.Remove(paths[j])
				}
			}
			return err
		}
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	return atomicWriteWithRename(path, data, os.Rename)
}

func atomicWriteWithRename(path string, data []byte, rename func(string, string) error) error {
	if err := inventory.Safe(filepath.Dir(path)); err != nil {
		return err
	}
	// Recheck the leaf without following it before creating any output.
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("output must be a regular file, not a symlink")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".underhood-%x.tmp", nonce))
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return rename(temp, path)
}
