// Package scan extracts bounded URL strings from ASCII and UTF-16LE byte streams.
package scan

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/inventory"
)

// Scanner bounds are independent of target type.
const (
	ChunkSize = 65536
	MaxRun    = 16384
	MaxURLs   = 10000
)

var deniedHosts = []string{"w3.org", "example.com", "localhost", "127.0.0.1"}
var namespacePaths = []string{"ns.adobe.com/", "ns.microsoft.com/", "purl.org/dc/", "xml.apache.org/", "java.sun.com/xml/ns/", "xmlns.jcp.org/"}
var urlPattern = regexp.MustCompile(`(?:https?|wss?)://[^\s<>"'\\]+`)

// Endpoint is a string occurrence, not observed traffic.
type Endpoint struct {
	URL, Host, Encoding string
	Offset              int64
}

// Result includes cap indicators so callers can disclose incomplete scans.
type Result struct {
	Endpoints                    []Endpoint
	Capped, LongRun, EndpointCap bool
}

// Allowed excludes namespace and placeholder noise used by the reference implementation.
func Allowed(host, value string) bool {
	host = strings.ToLower(host)
	value = strings.ToLower(value)
	for _, s := range deniedHosts {
		if host == s || strings.HasSuffix(host, "."+s) {
			return false
		}
	}
	for _, s := range namespacePaths {
		if strings.HasPrefix(value, "http://"+s) || strings.HasPrefix(value, "https://"+s) {
			return false
		}
	}
	if strings.HasPrefix(host, "schemas.") || strings.Contains(value, "/xmlns") || strings.Contains(value, "/xml/namespace") {
		return false
	}
	if host == "apple.com" || strings.HasSuffix(host, ".apple.com") {
		for _, s := range []string{".dtd", "/dtd", "/schema"} {
			if strings.Contains(value, s) {
				return false
			}
		}
	}
	return true
}

// File streams a safely opened regular file.
func File(path string, max int64) (Result, error) {
	f, e := inventory.Open(path)
	if e != nil {
		return Result{}, e
	}
	defer f.Close()
	return Reader(f, max, ChunkSize)
}

type run struct {
	buf      []byte
	start    int64
	overflow bool
	stride   int64
	encoding string
}

// Reader retains whole runs across chunk boundaries, including odd UTF-16 alignment.
func Reader(r io.Reader, max int64, chunk int) (Result, error) {
	result := Result{Endpoints: []Endpoint{}}
	if max <= 0 || chunk <= 0 || chunk > 16<<20 {
		return result, fmt.Errorf("invalid scan bounds")
	}
	seen := map[string]bool{}
	runs := []run{{stride: 1, encoding: "ASCII"}, {stride: 2, encoding: "UTF-16LE"}, {stride: 2, encoding: "UTF-16LE"}}
	flush := func(s *run) {
		if !s.overflow && len(s.buf) >= 7 {
			for _, m := range urlPattern.FindAllIndex(s.buf, -1) {
				value := strings.TrimRight(string(s.buf[m[0]:m[1]]), "),;]}")
				u, e := url.Parse(value)
				// The source is a raw string: malformed path escapes do not erase a valid host.
				if e != nil {
					start := strings.Index(value, "://") + 3
					if end := strings.IndexAny(value[start:], "/?#"); end >= 0 {
						u, e = url.Parse(value[:start+end])
					}
				}
				if e != nil || u.Hostname() == "" {
					continue
				}
				host := strings.ToLower(u.Hostname())
				if !Allowed(host, value) || seen[value] {
					continue
				}
				if len(result.Endpoints) >= MaxURLs {
					result.EndpointCap = true
					continue
				}
				seen[value] = true
				result.Endpoints = append(result.Endpoints, Endpoint{value, host, s.encoding, s.start + int64(m[0])*s.stride})
			}
		}
		s.buf = s.buf[:0]
		s.overflow = false
	}
	feed := func(s *run, b byte, valid bool, off int64) {
		if !valid {
			flush(s)
			return
		}
		if len(s.buf) == 0 && !s.overflow {
			s.start = off
		}
		if len(s.buf) < MaxRun && !s.overflow {
			s.buf = append(s.buf, b)
		} else {
			s.overflow = true
			result.LongRun = true
		}
	}
	b := make([]byte, chunk)
	var off int64
	var previous byte
	empty := 0
	for off < max {
		n, e := r.Read(b[:min(int64(chunk), max-off)])
		if n == 0 && e == nil {
			empty++
			if empty > 100 {
				return result, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
		for _, c := range b[:n] {
			feed(&runs[0], c, c >= 32 && c <= 126, off)
			if off > 0 {
				idx := 1 + int((off-1)%2)
				feed(&runs[idx], previous, c == 0 && previous >= 32 && previous <= 126, off-1)
			}
			previous = c
			off++
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, e
		}
	}
	var extra [1]byte
	n, e := r.Read(extra[:])
	if e != nil && e != io.EOF {
		return result, e
	}
	result.Capped = n > 0
	for i := range runs { // A partial trailing run at a scan cap cannot establish a complete URL.
		if result.Capped {
			runs[i].buf = nil
			runs[i].overflow = false
		} else {
			flush(&runs[i])
		}
	}
	sort.Slice(result.Endpoints, func(i, j int) bool {
		a, b := result.Endpoints[i], result.Endpoints[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		return a.Offset < b.Offset
	})
	return result, nil
}
