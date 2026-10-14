package macho

import (
	"bytes"
	"testing"
)

func TestBER(t *testing.T) {
	b := []byte{0x30, 0x80, 0x30, 0x80, 2, 1, 1, 0, 0, 0, 0}
	want := []byte{0x30, 5, 0x30, 3, 2, 1, 1}
	got, e := normalizeBER(b)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal(got, e)
	}
	for i := 0; i < len(b); i++ {
		if _, e := normalizeBER(b[:i]); e == nil {
			t.Fatal("accepted truncated BER", i)
		}
	}
}
