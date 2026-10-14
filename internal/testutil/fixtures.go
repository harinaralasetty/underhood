// Package testutil builds portable, synthetic fixtures without platform tools.
package testutil

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Info is the common dictionary used for XML/binary equivalence fixtures.
func Info() map[string]any {
	return map[string]any{"CFBundleName": "Fixture", "CFBundleIdentifier": "org.test.fixture", "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0", "CFBundleExecutable": "Fixture", "NSCameraUsageDescription": "Fixture camera declaration", "CFBundleURLTypes": []any{map[string]any{"CFBundleURLSchemes": []any{"fixture"}}}, "NSAppleScriptEnabled": true, "NSAppTransportSecurity": map[string]any{"NSAllowsArbitraryLoads": true}}
}

// XML encodes the fixture subset of plist types.
func XML(v any) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">`)
	var write func(any)
	text := func(s string) { xml.EscapeText(&b, []byte(s)) }
	write = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			b.WriteString("<dict>")
			keys := []string{}
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				b.WriteString("<key>")
				text(k)
				b.WriteString("</key>")
				write(x[k])
			}
			b.WriteString("</dict>")
		case []any:
			b.WriteString("<array>")
			for _, v := range x {
				write(v)
			}
			b.WriteString("</array>")
		case string:
			b.WriteString("<string>")
			text(x)
			b.WriteString("</string>")
		case bool:
			if x {
				b.WriteString("<true/>")
			} else {
				b.WriteString("<false/>")
			}
		case int64:
			fmt.Fprintf(&b, "<integer>%d</integer>", x)
		default:
			panic("unsupported fixture value")
		}
	}
	write(v)
	b.WriteString("</plist>")
	return b.Bytes()
}

// Binary encodes the same fixture subset with 16-bit references and 32-bit offsets.
func Binary(v any) []byte {
	var objects [][]byte
	var add func(any) uint16
	header := func(kind byte, n int) []byte {
		if n < 15 {
			return []byte{kind | byte(n)}
		}
		return []byte{kind | 15, 0x12, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	refs := func(ids []uint16) []byte {
		b := []byte{}
		for _, id := range ids {
			b = append(b, byte(id>>8), byte(id))
		}
		return b
	}
	add = func(v any) uint16 {
		id := uint16(len(objects))
		objects = append(objects, nil)
		var b []byte
		switch x := v.(type) {
		case string:
			b = append(header(0x50, len(x)), []byte(x)...)
		case bool:
			b = []byte{8}
			if x {
				b[0] = 9
			}
		case int64:
			b = make([]byte, 9)
			b[0] = 0x13
			binary.BigEndian.PutUint64(b[1:], uint64(x))
		case []any:
			ids := []uint16{}
			for _, v := range x {
				ids = append(ids, add(v))
			}
			b = append(header(0xa0, len(x)), refs(ids)...)
		case map[string]any:
			keys := []string{}
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			ids := []uint16{}
			for _, k := range keys {
				ids = append(ids, add(k))
			}
			for _, k := range keys {
				ids = append(ids, add(x[k]))
			}
			b = append(header(0xd0, len(x)), refs(ids)...)
		default:
			panic("unsupported fixture value")
		}
		objects[id] = b
		return id
	}
	root := add(v)
	b := []byte("bplist00")
	offsets := []uint32{}
	for _, o := range objects {
		offsets = append(offsets, uint32(len(b)))
		b = append(b, o...)
	}
	table := len(b)
	for _, off := range offsets {
		b = binary.BigEndian.AppendUint32(b, off)
	}
	t := make([]byte, 32)
	t[6] = 4
	t[7] = 2
	binary.BigEndian.PutUint64(t[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(t[16:], uint64(root))
	binary.BigEndian.PutUint64(t[24:], uint64(table))
	return append(b, t...)
}

// SuperBlob contains a CodeDirectory with explicit flags and XML entitlements.
func SuperBlob(flags uint32, ent map[string]any) []byte {
	cd := make([]byte, 52)
	cd = append(cd, []byte("org.test.fixture\x00TEAMTEST\x00")...)
	be := binary.BigEndian
	be.PutUint32(cd, 0xfade0c02)
	be.PutUint32(cd[4:], uint32(len(cd)))
	be.PutUint32(cd[8:], 0x20200)
	be.PutUint32(cd[12:], flags)
	be.PutUint32(cd[20:], 52)
	be.PutUint32(cd[48:], 69)
	xml := XML(ent)
	eb := make([]byte, 8)
	be.PutUint32(eb, 0xfade7171)
	be.PutUint32(eb[4:], uint32(8+len(xml)))
	eb = append(eb, xml...)
	b := make([]byte, 28)
	be.PutUint32(b, 0xfade0cc0)
	be.PutUint32(b[4:], uint32(len(b)+len(cd)+len(eb)))
	be.PutUint32(b[8:], 2)
	be.PutUint32(b[16:], 28)
	be.PutUint32(b[20:], 5)
	be.PutUint32(b[24:], uint32(28+len(cd)))
	b = append(b, cd...)
	return append(b, eb...)
}

// MachO builds an arm64 executable with LC_CODE_SIGNATURE and trailing strings.
func MachO(flags uint32, ent map[string]any) []byte {
	sig := SuperBlob(flags, ent)
	b := make([]byte, 48)
	le := binary.LittleEndian
	le.PutUint32(b, 0xfeedfacf)
	le.PutUint32(b[4:], 0x100000c)
	le.PutUint32(b[12:], 2)
	le.PutUint32(b[16:], 1)
	le.PutUint32(b[20:], 16)
	le.PutUint32(b[32:], 0x1d)
	le.PutUint32(b[36:], 16)
	le.PutUint32(b[40:], 48)
	le.PutUint32(b[44:], uint32(len(sig)))
	return append(b, sig...)
}

// URLs includes ASCII, UTF-16LE, noise, and a URL crossing a 64 KiB boundary.
func URLs() []byte {
	b := make([]byte, 65530)
	b = append(b, []byte("https://boundary.test/path\x00http://example.com/noise\x00https://ascii.test/a\x00")...)
	for _, c := range []byte("wss://utf16.test/socket") {
		b = append(b, c, 0)
	}
	return append(b, 0, 0)
}

// TempDir canonicalizes the platform's temporary directory before safe-open checks.
func TempDir(t testing.TB) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// Write creates a fixture file and its parents.
func Write(t testing.TB, path string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, b, 0644); e != nil {
		t.Fatal(e)
	}
}

// App creates a complete cross-platform bundle fixture.
func App(t testing.TB, binaryPlist bool) string {
	t.Helper()
	root := filepath.Join(TempDir(t), "Fixture.app")
	info := XML(Info())
	if binaryPlist {
		info = Binary(Info())
	}
	Write(t, filepath.Join(root, "Contents", "Info.plist"), info)
	exe := MachO(0x10000, map[string]any{"com.apple.security.app-sandbox": true, "com.apple.security.network.client": true, "com.apple.security.cs.disable-library-validation": true})
	exe = append(exe, URLs()...)
	Write(t, filepath.Join(root, "Contents", "MacOS", "Fixture"), exe)
	Write(t, filepath.Join(root, "Contents", "Library", "LaunchAgents", "job.plist"), XML(map[string]any{"Label": "org.test.fixture.job", "ProgramArguments": []any{"fixture", "--agent"}, "RunAtLoad": true}))
	Write(t, filepath.Join(root, "Contents", "Resources", "Fixture.sdef"), []byte(`<dictionary><suite name="Fixture Suite"><class name="document"/><command name="inspect"/></suite></dictionary>`))
	return root
}
