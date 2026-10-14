package testutil

import (
	"encoding/binary"
	"sort"
	"unicode/utf16"
)

func versionBlock(key, value string, children ...[]byte) []byte {
	b := make([]byte, 6)
	for _, u := range utf16.Encode([]rune(key + "\x00")) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	v := utf16.Encode([]rune(value + "\x00"))
	if value == "" {
		v = nil
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(v)))
	binary.LittleEndian.PutUint16(b[4:], 1)
	for _, u := range v {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	for _, child := range children {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		b = append(b, child...)
	}
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	return b
}

// PEResources constructs ID/name/language resource trees with file-backed data.
func PEResources(rva uint32, manifest string, versions map[string]string) []byte {
	var kinds []uint32
	var payloads [][]byte
	if len(versions) > 0 {
		keys := make([]string, 0, len(versions))
		for k := range versions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var fields [][]byte
		for _, k := range keys {
			fields = append(fields, versionBlock(k, versions[k]))
		}
		payloads = append(payloads, versionBlock("VS_VERSION_INFO", "", versionBlock("StringFileInfo", "", versionBlock("040904b0", "", fields...))))
		kinds = append(kinds, 16)
	}
	if manifest != "" {
		kinds = append(kinds, 24)
		payloads = append(payloads, []byte(manifest))
	}
	n := len(kinds)
	b := make([]byte, 16+8*n+64*n)
	binary.LittleEndian.PutUint16(b[14:], uint16(n))
	for i, k := range kinds {
		tree := 16 + 8*n + 64*i
		entry := 16 + 8*i
		binary.LittleEndian.PutUint32(b[entry:], k)
		binary.LittleEndian.PutUint32(b[entry+4:], uint32(tree)|0x80000000)
		for j := 0; j < 2; j++ {
			off := tree + j*24
			binary.LittleEndian.PutUint16(b[off+14:], 1)
			id := uint32(1)
			if j == 1 {
				id = 1033
			}
			binary.LittleEndian.PutUint32(b[off+16:], id)
			dest := uint32(off + 24)
			if j == 0 {
				dest |= 0x80000000
			}
			binary.LittleEndian.PutUint32(b[off+20:], dest)
		}
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		binary.LittleEndian.PutUint32(b[tree+48:], rva+uint32(len(b)))
		binary.LittleEndian.PutUint32(b[tree+52:], uint32(len(payloads[i])))
		b = append(b, payloads[i]...)
	}
	return b
}
