package testutil

import (
	"encoding/binary"
	"sort"
)

// PEOptions configures a synthetic host-independent image, never executable code.
type PEOptions struct {
	PE32               bool
	Machine, Subsystem uint16
	DLL, Managed       bool
	Imports            map[string][]string
	Manifest           string
	Version            map[string]string
	Certificate        []byte
}

// PE builds a minimal image with a bounded import section.
func PE(o PEOptions) []byte {
	b := make([]byte, 0x4200)
	u16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	u32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	copy(b, "MZ")
	u32(60, 128)
	copy(b[128:], "PE\x00\x00")
	machine := o.Machine
	if machine == 0 {
		machine = 0x8664
		if o.PE32 {
			machine = 0x14c
		}
	}
	u16(132, machine)
	u16(134, 1)
	opt := 240
	if o.PE32 {
		opt = 224
	}
	u16(148, uint16(opt))
	flags := uint16(2)
	if o.DLL {
		flags |= 0x2000
	}
	u16(150, flags)
	base := 152
	magic := uint16(0x20b)
	if o.PE32 {
		magic = 0x10b
	}
	u16(base, magic)
	u32(base+32, 0x1000)
	u32(base+36, 0x200)
	u16(base+40, 6)
	u16(base+48, 6)
	u32(base+56, 0x6000)
	u32(base+60, 0x200)
	sub := o.Subsystem
	if sub == 0 {
		sub = 3
	}
	u16(base+68, sub)
	u16(base+70, 0x140)
	dirs := base + 112
	if o.PE32 {
		dirs = base + 96
	}
	u32(dirs-4, 16)
	sec := base + opt
	copy(b[sec:], ".idata")
	u32(sec+8, 0x4000)
	u32(sec+12, 0x1000)
	u32(sec+16, 0x4000)
	u32(sec+20, 0x200)
	u32(sec+36, 0x40000040)
	if o.Managed {
		u32(dirs+14*8, 0x4f00)
		u32(dirs+14*8+4, 72)
	}
	names := make([]string, 0, len(o.Imports))
	for name := range o.Imports {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 0 {
		u32(dirs+8, 0x1000)
		u32(dirs+12, uint32((len(names)+1)*20))
	}
	cursor := 0x200 + (len(names)+1)*20
	rva := func(off int) uint32 { return uint32(off - 0x200 + 0x1000) }
	for i, name := range names {
		desc := 0x200 + i*20
		u32(desc+12, rva(cursor))
		copy(b[cursor:], name)
		cursor += len(name) + 1
		cursor = (cursor + 7) &^ 7
		width := 8
		if o.PE32 {
			width = 4
		}
		thunk := cursor
		u32(desc, rva(thunk))
		u32(desc+16, rva(thunk))
		cursor += (len(o.Imports[name]) + 1) * width
		for j, symbol := range o.Imports[name] {
			u32(thunk+j*width, rva(cursor))
			copy(b[cursor+2:], symbol)
			cursor += len(symbol) + 3
		}
	}

	if o.Manifest != "" || len(o.Version) > 0 {
		resources := PEResources(0x6000, o.Manifest, o.Version)
		padded := (len(resources) + 511) &^ 511
		b = append(b, make([]byte, padded)...)
		copy(b[0x4200:], resources)
		u16(134, 2)
		u32(base+56, 0x6000+uint32((padded+4095)&^4095))
		u32(dirs+16, 0x6000)
		u32(dirs+20, uint32(len(resources)))
		sec += 40
		copy(b[sec:], ".rsrc")
		u32(sec+8, uint32(len(resources)))
		u32(sec+12, 0x6000)
		u32(sec+16, uint32(padded))
		u32(sec+20, 0x4200)
		u32(sec+36, 0x40000040)
	}

	if len(o.Certificate) > 0 {
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
		off := len(b)
		n := 8 + len(o.Certificate)
		aligned := (n + 7) &^ 7
		b = append(b, make([]byte, aligned)...)
		u32(dirs+4*8, uint32(off))
		u32(dirs+4*8+4, uint32(aligned))
		u32(off, uint32(n))
		u16(off+4, 0x200)
		u16(off+6, 2)
		copy(b[off+8:], o.Certificate)
	}
	return b
}
