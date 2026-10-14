package scan_test

import (
	"bytes"
	"fmt"
	"github.com/harinaralasetty/underhood/internal/scan"
	"github.com/harinaralasetty/underhood/internal/testutil"
	"strings"
	"testing"
)

func TestStreams(t *testing.T) {
	for _, chunk := range []int{1, 7, 65536} {
		r, e := scan.Reader(bytes.NewReader(testutil.URLs()), 1<<20, chunk)
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Endpoints) != 3 {
			t.Fatalf("chunk=%d %+v", chunk, r)
		}
		for _, ep := range r.Endpoints {
			if ep.Host == "boundary.test" && ep.URL != "https://boundary.test/path" {
				t.Fatal(ep)
			}
			if ep.Host == "utf16.test" && ep.Encoding != "UTF-16LE" {
				t.Fatal(ep)
			}
		}
	}
}
func TestCaps(t *testing.T) {
	r, e := scan.Reader(strings.NewReader("https://valid.test/longpath"), 15, 3)
	if e != nil || !r.Capped || len(r.Endpoints) != 0 {
		t.Fatal(r, e)
	}
	r, e = scan.Reader(strings.NewReader("https://valid.test/"+strings.Repeat("x", scan.MaxRun)), 100000, 17)
	if e != nil || !r.LongRun || len(r.Endpoints) != 0 {
		t.Fatal(r, e)
	}
	var b strings.Builder
	for i := 0; i < scan.MaxURLs+1; i++ {
		fmt.Fprintf(&b, "https://cap.test/%d\x00", i)
	}
	r, e = scan.Reader(strings.NewReader(b.String()), 1<<20, scan.ChunkSize)
	if e != nil || !r.EndpointCap || len(r.Endpoints) != scan.MaxURLs {
		t.Fatal(len(r.Endpoints), r.EndpointCap, e)
	}
}

func TestOddUTF16AndBoundaryOffset(t *testing.T) {
	var b []byte
	b = append(b, 0xff)
	value := "https://odd.test/a"
	for _, c := range []byte(value) {
		b = append(b, c, 0)
	}
	b = append(b, 0, 0)
	r, e := scan.Reader(bytes.NewReader(b), 1000, 3)
	if e != nil || len(r.Endpoints) != 1 || r.Endpoints[0].Offset != 1 || r.Endpoints[0].URL != value {
		t.Fatal(r, e)
	}
	r, e = scan.Reader(bytes.NewReader(testutil.URLs()), 1<<20, 65536)
	if e != nil {
		t.Fatal(e)
	}
	for _, ep := range r.Endpoints {
		if ep.Host == "boundary.test" && ep.Offset != 65530 {
			t.Fatal(ep)
		}
	}
}

func TestRawPathEscapes(t *testing.T) {
	r, e := scan.Reader(strings.NewReader("http://cert.test/root.cer0%\x00"), 1000, 7)
	if e != nil || len(r.Endpoints) != 1 || r.Endpoints[0].Host != "cert.test" {
		t.Fatal(r, e)
	}
}
