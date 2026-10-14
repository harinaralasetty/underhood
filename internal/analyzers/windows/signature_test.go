package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"testing"
)

func signatureFixture(t *testing.T) []byte {
	t.Helper()
	b, err := testutil.PKCS7()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestPKCS7(t *testing.T) {
	b := signatureFixture(t)
	info, e := ParsePKCS7(b)
	if e != nil {
		t.Fatal(e)
	}
	if len(info.Signers) != 1 || len(info.Chains) != 1 || len(info.Chains[0]) != 1 || info.Signers[0].Subject.CommonName != "Synthetic signer" {
		t.Fatalf("signer chain: %+v", info)
	}
	if len(info.DigestOIDs) != 1 || info.DigestOIDs[0] != "2.16.840.1.101.3.4.2.1" || len(info.TimestampOIDs) != 2 {
		t.Fatalf("algorithms/timestamps: %+v", info)
	}
	for n := 0; n < len(b); n++ {
		if _, e := ParsePKCS7(b[:n]); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	if _, e := ParsePKCS7(append(b, 0)); e == nil {
		t.Fatal("accepted trailing byte")
	}
}
func TestCertificateTable(t *testing.T) {
	der := signatureFixture(t)
	entry := make([]byte, (8+len(der)+7)&^7)
	binary.LittleEndian.PutUint32(entry, uint32(8+len(der)))
	binary.LittleEndian.PutUint16(entry[4:], 0x200)
	binary.LittleEndian.PutUint16(entry[6:], 2)
	copy(entry[8:], der)
	b := append(make([]byte, 32), entry...)
	p := &pe.File{OptionalHeader: &pe.OptionalHeader64{NumberOfRvaAndSizes: 16}}
	h := p.OptionalHeader.(*pe.OptionalHeader64)
	h.DataDirectory[4] = pe.DataDirectory{VirtualAddress: 32, Size: uint32(len(entry))}
	f, s := analyzeSignatures(bytes.NewReader(b), int64(len(b)), p, "test.exe")
	if len(s) != 0 || len(f) != 1 || f[0].ID != "windows.pe.signature@test.exe" {
		t.Fatalf("findings=%+v skips=%+v", f, s)
	}
	expired := false
	for _, ev := range f[0].Evidence {
		if ev.Locator == "WIN_CERTIFICATE[0].signer[0].expiry" {
			expired = true
		}
	}
	if !expired {
		t.Fatal("missing expiry context")
	}
	for n := 32; n < len(b); n++ {
		_, s := analyzeSignatures(bytes.NewReader(b[:n]), int64(n), p, "")
		if len(s) == 0 {
			t.Fatalf("truncation %d missing skip", n)
		}
	}
	// Multiple aligned certificate entries retain one stable finding and both locators.
	double := append(append([]byte(nil), b...), entry...)
	h.DataDirectory[4].Size = uint32(2 * len(entry))
	multi, notes := analyzeSignatures(bytes.NewReader(double), int64(len(double)), p, "test.exe")
	if len(notes) != 0 || len(multi) != 1 || len(multi[0].Evidence) != 2*len(f[0].Evidence) {
		t.Fatalf("multiple entries: %+v %+v", multi, notes)
	}
	for _, length := range []uint32{0, 7, 0xffffffff} {
		broken := append([]byte(nil), b...)
		binary.LittleEndian.PutUint32(broken[32:], length)
		h.DataDirectory[4].Size = uint32(len(entry))
		bad, notes := analyzeSignatures(bytes.NewReader(broken), int64(len(broken)), p, "")
		if len(notes) == 0 || len(bad) != 1 || bad[0].ID != "windows.pe.signature-unparsable" {
			t.Fatalf("bad length %d: %+v %+v", length, bad, notes)
		}
	}
	h.DataDirectory[4] = pe.DataDirectory{}
	f, s = analyzeSignatures(bytes.NewReader(b), int64(len(b)), p, "")
	if len(s) != 0 || len(f) != 1 || f[0].ID != "windows.pe.unsigned" {
		t.Fatal(f, s)
	}
}
func FuzzPKCS7(f *testing.F) {
	if b, err := testutil.PKCS7(); err == nil {
		f.Add(b)
	} else {
		f.Fatal(err)
	}
	f.Add([]byte{0x30, 0})
	f.Add([]byte("PKCX"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParsePKCS7(b) })
}
