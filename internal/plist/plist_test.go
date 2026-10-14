package plist_test

import (
	"bytes"
	"github.com/harinaralasetty/underhood/internal/plist"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"reflect"
	"testing"
)

func TestFormats(t *testing.T) {
	want := testutil.Info()
	for _, b := range [][]byte{testutil.XML(want), testutil.Binary(want)} {
		got, e := plist.Decode(b)
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, %v", got, e)
		}
	}
}
func TestTruncations(t *testing.T) {
	for _, b := range [][]byte{testutil.XML(testutil.Info()), testutil.Binary(testutil.Info())} {
		for i := 0; i < len(b); i++ {
			if _, e := plist.Decode(b[:i]); e == nil {
				t.Fatalf("accepted truncation %d/%d", i, len(b))
			}
		}
	}
	for _, b := range [][]byte{[]byte(`<plist><dict><key>x</key></dict></plist>`), []byte(`<plist><dict/><dict/></plist>`), bytes.Repeat([]byte{'x'}, (16<<20)+1)} {
		if _, e := plist.Decode(b); e == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(testutil.XML(testutil.Info()))
	f.Add(testutil.Binary(testutil.Info()))
	f.Add([]byte("bplist00"))
	f.Fuzz(func(t *testing.T, b []byte) { plist.Decode(b) })
}

func TestScalarTypesAndMalformedReferences(t *testing.T) {
	// Binary dict with key x and one scalar/container value, using one-byte references.
	wrap := func(value []byte) []byte {
		b := append([]byte("bplist00"), 0xd1, 1, 2, 0x51, 'x')
		off := len(b)
		b = append(b, value...)
		table := len(b)
		b = append(b, 8, 11, byte(off))
		trailer := make([]byte, 32)
		trailer[6] = 1
		trailer[7] = 1
		trailer[15] = 3
		trailer[31] = byte(table)
		return append(b, trailer...)
	}
	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"real", []byte{0x23, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0}}, {"date", []byte{0x33, 0, 0, 0, 0, 0, 0, 0, 0}}, {"data", []byte{0x42, 1, 2}}, {"utf16", []byte{0x62, 0, 65, 0x03, 0xa9}}, {"uid", []byte{0x80, 7}}, {"set", []byte{0xc1, 1}}, {"orderedSet", []byte{0xb1, 1}}, {"int128", []byte{0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, e := plist.Decode(wrap(tc.blob))
			if e != nil || d["x"] == nil {
				t.Fatal(d, e)
			}
		})
	}
	for _, blob := range [][]byte{{0xa1, 2}, {0xa1, 255}, {0x6f, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		if _, e := plist.Decode(wrap(blob)); e == nil {
			t.Fatal("accepted cycle/reference/length")
		}
	}
}

func TestReferenceExpansionCap(t *testing.T) {
	// Reuse a 1 MiB data object 100 times, despite a small encoded plist.
	b := []byte("bplist00")
	offsets := []uint32{8, 11, 13}
	b = append(b, 0xd1, 1, 2, 0x51, 'x', 0xaf, 0x11, 0, 100)
	for i := 0; i < 100; i++ {
		b = append(b, 3)
	}
	offsets = append(offsets, uint32(len(b)))
	b = append(b, 0x4f, 0x12, 0, 16, 0, 0)
	b = append(b, make([]byte, 1<<20)...)
	table := len(b)
	for _, off := range offsets {
		b = append(b, byte(off>>24), byte(off>>16), byte(off>>8), byte(off))
	}
	trailer := make([]byte, 32)
	trailer[6] = 4
	trailer[7] = 1
	trailer[15] = 4
	trailer[28] = byte(table >> 24)
	trailer[29] = byte(table >> 16)
	trailer[30] = byte(table >> 8)
	trailer[31] = byte(table)
	b = append(b, trailer...)
	if _, e := plist.Decode(b); e == nil {
		t.Fatal("reference expansion was unbounded")
	}
}
