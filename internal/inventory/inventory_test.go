package inventory_test

import (
	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestSafetyAndCaps(t *testing.T) {
	root := testutil.App(t, false)
	external := filepath.Join(testutil.TempDir(t), "outside")
	testutil.Write(t, external, []byte("private"))
	link := filepath.Join(root, "escape")
	if e := os.Symlink(external, link); e == nil {
		v := inventory.Walk(root, 20000)
		if len(v.ExternalSymlinks) != 1 {
			t.Fatal(v.ExternalSymlinks)
		}
		if _, e := inventory.Open(link); e == nil {
			t.Fatal("opened symlink")
		}
	}
	v := inventory.Walk(root, 2)
	if len(v.Notes) == 0 {
		t.Fatal("missing file cap")
	}
	p := root
	for i := 0; i < 5; i++ {
		p = filepath.Join(p, "Nested.app")
	}
	testutil.Write(t, filepath.Join(p, "hidden"), []byte("x"))
	v = inventory.Walk(root, 20000)
	for _, f := range v.Files {
		if f == filepath.Join(p, "hidden") {
			t.Fatal("depth cap failed")
		}
	}
	if len(v.Notes) == 0 {
		t.Fatal("missing depth note")
	}
}

func TestMetadataCap(t *testing.T) {
	p := filepath.Join(testutil.TempDir(t), "large.plist")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate((16 << 20) + 1); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e := inventory.ReadMetadata(p); e == nil {
		t.Fatal("metadata cap not enforced")
	}
}
