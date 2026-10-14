package macho_test

import (
	"bytes"
	"encoding/binary"
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"testing"
)

func TestSignature(t *testing.T) {
	flags := macho.Adhoc | macho.RequireLibraryValidation | macho.HardenedRuntime | macho.LinkerSigned
	b := testutil.SuperBlob(flags, map[string]any{"com.apple.security.app-sandbox": true})
	s, e := macho.ParseSuperBlob(b)
	if e != nil {
		t.Fatal(e)
	}
	cd := s.Directories[0]
	if cd.Flags != flags || cd.Identifier != "org.test.fixture" || cd.TeamID != "TEAMTEST" || s.Entitlements["com.apple.security.app-sandbox"] != true {
		t.Fatalf("%+v %+v", cd, s)
	}
	for i := 0; i < len(b); i++ {
		if _, e := macho.ParseSuperBlob(b[:i]); e == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}
func TestThinAndFat(t *testing.T) {
	a := testutil.MachO(macho.HardenedRuntime, map[string]any{"value": true})
	b := testutil.MachO(macho.Adhoc, map[string]any{"value": false})
	fat := make([]byte, 48)
	be := binary.BigEndian
	be.PutUint32(fat, 0xcafebabe)
	be.PutUint32(fat[4:], 2)
	for i, p := range [][]byte{a, b} {
		o := 8 + i*20
		be.PutUint32(fat[o:], 0x100000c)
		be.PutUint32(fat[o+8:], uint32(len(fat)))
		be.PutUint32(fat[o+12:], uint32(len(p)))
		fat = append(fat, p...)
	}
	for _, data := range [][]byte{a, fat} {
		s, e := macho.Read(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			t.Fatal(e)
		}
		if len(s) == 0 || s[0].Signature == nil || s[0].Architecture != "arm64" {
			t.Fatalf("%+v", s)
		}
		if len(s) == 2 && s[0].Signature.Directories[0].Flags == s[1].Signature.Directories[0].Flags {
			t.Fatal("lost slice differences")
		}
	}
	for i := 0; i < 48; i++ {
		macho.Read(bytes.NewReader(a[:i]), int64(i))
	}
}
func FuzzSuperBlob(f *testing.F) {
	f.Add(testutil.SuperBlob(macho.HardenedRuntime, map[string]any{"x": true}))
	f.Add([]byte{0xfa, 0xde, 0x0c, 0xc0})
	f.Fuzz(func(t *testing.T, b []byte) { macho.ParseSuperBlob(b) })
}

func TestMalformedOffsets(t *testing.T) {
	original := testutil.SuperBlob(0, map[string]any{})
	for _, at := range []int{4, 8, 16, 24} {
		b := append([]byte{}, original...)
		binary.BigEndian.PutUint32(b[at:], 0xffffffff)
		if _, e := macho.ParseSuperBlob(b); e == nil {
			t.Fatalf("accepted bad field %d", at)
		}
	}
}

func TestLibrariesWithoutSymbolReads(t *testing.T) {
	b := make([]byte, 32)
	le := binary.LittleEndian
	le.PutUint32(b, 0xfeedfacf)
	le.PutUint32(b[4:], 0x100000c)
	le.PutUint32(b[12:], 2)
	for _, cmd := range []uint32{0xc, 0x80000018} {
		c := make([]byte, 24)
		le.PutUint32(c, cmd)
		le.PutUint32(c[8:], 24)
		c = append(c, []byte("@rpath/Fixture.dylib\x00")...)
		le.PutUint32(c[4:], uint32(len(c)))
		b = append(b, c...)
	}
	// A huge unused symbol table must not be read merely to inspect linked libraries.
	sym := make([]byte, 24)
	le.PutUint32(sym, 2)
	le.PutUint32(sym[4:], 24)
	le.PutUint32(sym[12:], 0xffffffff)
	le.PutUint32(sym[20:], 0xffffffff)
	b = append(b, sym...)
	le.PutUint32(b[16:], 3)
	le.PutUint32(b[20:], uint32(len(b)-32))
	s, e := macho.Read(bytes.NewReader(b), int64(len(b)))
	if e != nil || len(s) != 1 || len(s[0].Libraries) != 2 {
		t.Fatal(s, e)
	}
}
