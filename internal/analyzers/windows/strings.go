package windows

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/scan"
)

var persistenceStrings = []string{`\CurrentVersion\Run`, `\CurrentVersion\RunOnce`, `\Services\`, `\Winlogon\`, `Image File Execution Options`, `schtasks`, `\Startup\`}

func analyzeStrings(r io.ReaderAt, size int64, label string, opts model.Options) ([]model.Finding, []model.SkipNote) {
	max := opts.MaxBinaryMB
	if max <= 0 {
		max = model.DefaultBinaryMB
	}
	if max > 1<<20 {
		max = 1 << 20
	}
	limit := max << 20
	var f []model.Finding
	var skips []model.SkipNote
	result, e := scan.Reader(io.NewSectionReader(r, 0, size), limit, scan.ChunkSize)
	if e != nil {
		skips = append(skips, peNote(label, "binary strings: "+e.Error()))
	}
	if result.Capped {
		skips = append(skips, peNote(label, "binary string byte cap reached"))
	}
	if result.LongRun {
		skips = append(skips, peNote(label, "overlong binary string runs skipped"))
	}
	if result.EndpointCap {
		skips = append(skips, peNote(label, "endpoint scan cap reached"))
	}
	hosts := map[string][]model.Evidence{}
	retained := 0
	file := label
	if file == "" {
		file = "."
	}
	for _, v := range result.Endpoints {
		if _, ok := hosts[v.Host]; !ok && len(hosts) >= model.MaxHosts {
			continue
		}
		if len(hosts[v.Host]) >= model.MaxHostEvidence {
			continue
		}
		hosts[v.Host] = append(hosts[v.Host], model.Evidence{File: file, Locator: fmt.Sprintf("%s offset %#x", v.Encoding, v.Offset), Value: v.URL})
		retained++
	}
	names := make([]string, 0, len(hosts))
	for host := range hosts {
		names = append(names, host)
	}
	sort.Strings(names)
	for _, host := range names {
		finding := peFinding("net.host."+host, "network", "Endpoint string host: "+host, "URL string present in a binary, not verified traffic; not proof of use; common in legitimate tools and in malware; presence does not establish use.", model.Notable, model.Binary, "", "", "")
		finding.Evidence = hosts[host]
		f = append(f, finding)
	}
	if len(result.Endpoints) > retained {
		skips = append(skips, peNote(label, "endpoint host/evidence caps reached"))
	}
	// Fixed-size streaming windows cover both ASCII and UTF-16LE at either alignment.
	patterns := make([][]byte, 0, len(persistenceStrings)*2)
	for _, s := range persistenceStrings {
		a := []byte(strings.ToLower(s))
		patterns = append(patterns, a)
		wide := make([]byte, len(a)*2)
		for i, b := range a {
			wide[i*2] = b
		}
		patterns = append(patterns, wide)
	}
	found := make([]bool, len(persistenceStrings))
	buf := make([]byte, scan.ChunkSize+128)
	carry := 0
	var off int64
	for off < min(size, limit) {
		n := int(min(int64(scan.ChunkSize), min(size, limit)-off))
		got, err := r.ReadAt(buf[carry:carry+n], off)
		if got == 0 {
			break
		}
		window := append([]byte(nil), buf[:carry+got]...)
		for i, c := range window {
			if c >= 'A' && c <= 'Z' {
				window[i] = c + ('a' - 'A')
			}
		}
		for i, p := range patterns {
			idx := i / 2
			if found[idx] {
				continue
			}
			pos := bytes.Index(window, p)
			if pos >= 0 {
				found[idx] = true
				f = append(f, peFinding(fmt.Sprintf("windows.persistence.%d", idx), "capabilities", "Persistence-related path string", "String present, not proof of use; common in legitimate tools and in malware; presence does not establish use.", model.Notable, model.Binary, label, fmt.Sprintf("binary offset %#x", off-int64(carry)+int64(pos)), persistenceStrings[idx]))
			}
		}
		total := carry + got
		carry = min(128, total)
		copy(buf, buf[total-carry:total])
		off += int64(got)
		if err != nil {
			if err != io.EOF {
				skips = append(skips, peNote(label, "path string scan: "+err.Error()))
			}
			break
		}
	}
	return f, skips
}
