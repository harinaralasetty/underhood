// Package inventory walks targets without traversing symbolic links.
package inventory

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
)

// Inventory contains only regular files and safe directories.
type Inventory struct {
	Files, Directories, Bundles, Binaries, ExternalSymlinks []string
	Notes                                                   []model.SkipNote
}

// Safe checks every path component with Lstat, including parent directories.
func Safe(path string) error {
	p, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink not traversed: %s", p)
		}
		next := filepath.Dir(p)
		if next == p {
			break
		}
		p = next
	}
	return nil
}

// Open opens a regular file after checking its components and identity.
func Open(path string) (*os.File, error) {
	if e := Safe(path); e != nil {
		return nil, e
	}
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, fmt.Errorf("file changed while opening: %s", path)
	}
	return f, nil
}

// ReadMetadata enforces the per-file metadata bound.
func ReadMetadata(path string) ([]byte, error) {
	f, e := Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, model.MaxMetadata+1))
	if len(b) > model.MaxMetadata {
		return nil, fmt.Errorf("metadata cap of 16 MiB reached")
	}
	return b, e
}

// Relative returns a portable path relative to root.
func Relative(root, path string) string {
	p, e := filepath.Rel(root, path)
	if e != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(p)
}

// IsMachO recognizes thin and fat magic in either byte order.
func IsMachO(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(b[:4]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return true
	}
	return false
}
func bundle(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".app", ".framework", ".xpc", ".appex", ".bundle", ".plugin":
		return true
	}
	return false
}

// Walk inventories at most maxFiles entries and four nested bundle levels.
func Walk(root string, maxFiles int) Inventory {
	v := Inventory{Bundles: []string{root}}
	count := 0
	note := func(p, s string) {
		v.Notes = append(v.Notes, model.SkipNote{Analyzer: "Inventory", File: Relative(root, p), Reason: s, Count: 1})
	}
	if e := Safe(root); e != nil {
		note(root, e.Error())
		return v
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			note(p, e.Error())
			return nil
		}
		if p == root {
			return nil
		}
		if count >= maxFiles {
			note(root, fmt.Sprintf("file-count cap of %d reached", maxFiles))
			return fs.SkipAll
		}
		count++
		if d.Type()&os.ModeSymlink != 0 {
			dest, e := os.Readlink(p)
			if e == nil {
				if !filepath.IsAbs(dest) {
					dest = filepath.Join(filepath.Dir(p), dest)
				}
				rel := Relative(root, dest)
				if rel == ".." || strings.HasPrefix(rel, "../") {
					v.ExternalSymlinks = append(v.ExternalSymlinks, p)
				}
			}
			note(p, "symlink not traversed")
			return nil
		}
		if d.IsDir() {
			depth := 0
			parts := strings.Split(Relative(root, p), "/")
			for _, part := range parts {
				if bundle(part) {
					depth++
				}
			}
			if depth > model.MaxDepth {
				note(p, "nested-bundle depth cap of 4 reached")
				return fs.SkipDir
			}
			if len(parts) > 64 {
				note(p, "directory depth cap of 64 reached")
				return fs.SkipDir
			}
			v.Directories = append(v.Directories, p)
			if bundle(p) {
				v.Bundles = append(v.Bundles, p)
			}
			return nil
		}
		info, e := d.Info()
		if e != nil {
			note(p, e.Error())
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		v.Files = append(v.Files, p)
		f, e := Open(p)
		if e != nil {
			note(p, e.Error())
			return nil
		}
		var magic [4]byte
		n, _ := f.Read(magic[:])
		f.Close()
		if n == 4 && IsMachO(magic[:]) {
			v.Binaries = append(v.Binaries, p)
		}
		return nil
	})
	if err != nil {
		note(root, err.Error())
	}
	sort.Strings(v.Files)
	sort.Strings(v.Bundles)
	sort.Strings(v.Binaries)
	return v
}
