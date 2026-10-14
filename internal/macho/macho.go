// Package macho parses Mach-O slices and embedded signatures without verification.
package macho

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/model"
)

// Slice carries facts and recoverable errors for one architecture.
type Slice struct {
	Architecture string
	Offset       int64
	Libraries    []string
	Signature    *Signature
	Error        string
}

// Parse reads bounded headers and signature metadata from every fat slice.
func Parse(path string) ([]Slice, error) {
	f, e := inventory.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	return Read(f, st.Size())
}

// Read parses a random-access binary. The caller controls the reader lifetime.
func Read(r io.ReaderAt, size int64) ([]Slice, error) {
	if size < 4 {
		return nil, errors.New("truncated Mach-O")
	}
	var head [8]byte
	if _, e := r.ReadAt(head[:], 0); e != nil {
		return nil, e
	}
	magic := binary.BigEndian.Uint32(head[:4])
	var order binary.ByteOrder = binary.BigEndian
	fat := magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca
	if !fat {
		s, e := thin(r, size)
		return []Slice{s}, e
	}
	if magic == 0xbebafeca || magic == 0xbfbafeca {
		order = binary.LittleEndian
	}
	count := order.Uint32(head[4:])
	if count == 0 || count > 128 {
		return nil, errors.New("fat slice count cap or invalid count")
	}
	entry := int64(20)
	if magic == 0xcafebabf || magic == 0xbfbafeca {
		entry = 32
	}
	tableEnd := 8 + int64(count)*entry
	if tableEnd > size {
		return nil, errors.New("truncated fat table")
	}
	out := []Slice{}
	for i := uint32(0); i < count; i++ {
		b := make([]byte, entry)
		if _, e := r.ReadAt(b, 8+int64(i)*entry); e != nil {
			return nil, e
		}
		off, n := uint64(order.Uint32(b[8:])), uint64(order.Uint32(b[12:]))
		if entry == 32 {
			off = order.Uint64(b[8:])
			n = order.Uint64(b[16:])
		}
		s := Slice{Architecture: arch(order.Uint32(b), order.Uint32(b[4:])), Offset: int64(off)}
		if off < uint64(tableEnd) || off > uint64(size) || n > uint64(size)-off || n < 28 {
			s.Error = "invalid fat slice bounds"
		} else {
			parsed, e := thin(io.NewSectionReader(r, int64(off), int64(n)), int64(n))
			parsed.Offset = int64(off)
			if e != nil {
				parsed.Error = e.Error()
			}
			s = parsed
		}
		out = append(out, s)
	}
	return out, nil
}
func arch(cpu, sub uint32) string {
	switch cpu {
	case 7:
		return "i386"
	case 0x1000007:
		if sub&0xffffff == 8 {
			return "x86_64h"
		}
		return "x86_64"
	case 12:
		return "arm"
	case 0x100000c:
		if sub&0xffffff == 12 {
			return "arm64e.x1"
		}
		if sub&0xffffff == 2 {
			return "arm64e"
		}
		return "arm64"
	case 18:
		return "ppc"
	case 0x1000012:
		return "ppc64"
	}
	return fmt.Sprintf("cpu-0x%x-sub-0x%x", cpu, sub)
}
func thin(r io.ReaderAt, size int64) (Slice, error) {
	s := Slice{}
	var h [32]byte
	if size < 28 {
		return s, errors.New("truncated Mach-O header")
	}
	if _, e := r.ReadAt(h[:28], 0); e != nil {
		return s, e
	}
	magic := binary.BigEndian.Uint32(h[:4])
	var o binary.ByteOrder = binary.BigEndian
	header := int64(28)
	switch magic {
	case 0xcefaedfe:
		o = binary.LittleEndian
	case 0xcffaedfe:
		o = binary.LittleEndian
		header = 32
	case 0xfeedfacf:
		header = 32
	case 0xfeedface:
	default:
		return s, errors.New("invalid Mach-O magic")
	}
	s.Architecture = arch(o.Uint32(h[4:]), o.Uint32(h[8:]))
	count, n := o.Uint32(h[16:]), o.Uint32(h[20:])
	if n > model.MaxMetadata || int64(n) > size-header || count > n/8 {
		return s, errors.New("invalid or excessive load commands")
	}
	b := make([]byte, n)
	if _, e := r.ReadAt(b, header); e != nil {
		return s, e
	}
	pos := 0
	var sigoff, siglen uint32
	var libraryCommands []byte
	var libraryCount uint32
	for i := uint32(0); i < count; i++ {
		if len(b)-pos < 8 {
			return s, errors.New("truncated load command")
		}
		cmd, l := o.Uint32(b[pos:]), o.Uint32(b[pos+4:])
		if l < 8 || uint64(l) > uint64(len(b)-pos) {
			return s, errors.New("invalid load command size")
		}
		c := b[pos : pos+int(l)]
		switch cmd {
		case 0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023:
			if len(c) < 24 {
				return s, errors.New("truncated dylib command")
			}
			nameOffset := o.Uint32(c[8:])
			if nameOffset < 24 || uint64(nameOffset) >= uint64(len(c)) {
				return s, errors.New("invalid dylib name offset")
			}
			end := bytes.IndexByte(c[nameOffset:], 0)
			if end < 0 {
				return s, errors.New("unterminated dylib name")
			}
			if cmd == 0xc {
				libraryCommands = append(libraryCommands, c...)
				libraryCount++
			} else {
				s.Libraries = append(s.Libraries, string(c[nameOffset:int(nameOffset)+end]))
			}
		case 0x1d:
			if len(c) < 16 {
				return s, errors.New("truncated code signature command")
			}
			sigoff, siglen = o.Uint32(c[8:]), o.Uint32(c[12:])
		case 1:
			if len(c) < 56 || uint64(o.Uint32(c[48:])) > uint64(len(c)-56)/68 {
				return s, errors.New("invalid segment sections")
			}
		case 0x19:
			if len(c) < 72 || uint64(o.Uint32(c[64:])) > uint64(len(c)-72)/80 {
				return s, errors.New("invalid segment64 sections")
			}
		}
		pos += int(l)
	}
	// Give debug/macho only the dylib commands it understands. Unneeded symbol,
	// relocation and section tables never trigger reads or allocations.
	libraryHeader := append([]byte{}, h[:header]...)
	o.PutUint32(libraryHeader[16:], libraryCount)
	o.PutUint32(libraryHeader[20:], uint32(len(libraryCommands)))
	mf, e := macho.NewFile(bytes.NewReader(append(libraryHeader, libraryCommands...)))
	if e != nil {
		return s, e
	}
	libraries, e := mf.ImportedLibraries()
	s.Libraries = append(s.Libraries, libraries...)
	if e != nil {
		return s, e
	}
	sort.Strings(s.Libraries)
	if siglen == 0 {
		return s, nil
	}
	if siglen > model.MaxMetadata || uint64(sigoff)+uint64(siglen) > uint64(size) {
		return s, errors.New("invalid signature bounds or metadata cap of 16 MiB reached")
	}
	data := make([]byte, siglen)
	if _, e = r.ReadAt(data, int64(sigoff)); e != nil {
		return s, e
	}
	s.Signature, e = ParseSuperBlob(data)
	return s, e
}
