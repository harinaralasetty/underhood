package macho

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/plist"
)

// Signature flags from Apple's XNU cs_blobs.h.
const (
	Adhoc                    uint32 = 0x2
	RequireLibraryValidation uint32 = 0x2000
	HardenedRuntime          uint32 = 0x10000
	LinkerSigned             uint32 = 0x20000
)

// CodeDirectory records signing metadata, not a verified identity.
type CodeDirectory struct {
	Slot, Magic, Length, Version, Flags                         uint32
	HashOffset, IdentOffset, SpecialSlots, CodeSlots, CodeLimit uint32
	HashSize, HashType, Platform, PageSize                      uint8
	Spare2, ScatterOffset, TeamOffset                           uint32
	Identifier, TeamID                                          string
}

// Signature holds parsed signature components; Notes describe unavailable details.
type Signature struct {
	Directories            []CodeDirectory
	Entitlements           map[string]any
	HasXML, HasDER, HasCMS bool
	Authorities, Notes     []string
	EntitlementError       string
}

// FlagText interprets documented flags while retaining all raw bits.
func FlagText(flags uint32) string {
	var names []string
	for _, v := range []struct {
		bit  uint32
		name string
	}{{Adhoc, "adhoc"}, {RequireLibraryValidation, "library-validation"}, {HardenedRuntime, "runtime"}, {LinkerSigned, "linker-signed"}} {
		if flags&v.bit != 0 {
			names = append(names, v.name)
		}
	}
	return fmt.Sprintf("flags=0x%x(%s)", flags, strings.Join(names, ","))
}

// ParseSuperBlob validates offsets and decodes signing metadata. It never verifies signatures.
func ParseSuperBlob(data []byte) (*Signature, error) {
	if len(data) < 12 || len(data) > model.MaxMetadata {
		return nil, errors.New("truncated or excessive SuperBlob")
	}
	be := binary.BigEndian
	if be.Uint32(data) != 0xfade0cc0 {
		return nil, errors.New("invalid SuperBlob magic")
	}
	length, count := uint64(be.Uint32(data[4:])), uint64(be.Uint32(data[8:]))
	if length > uint64(len(data)) || length < 12 || count > (length-12)/8 {
		return nil, errors.New("invalid SuperBlob length/index")
	}
	data = data[:length]
	s := &Signature{Entitlements: map[string]any{}}
	slots := map[uint32]bool{}
	for i := uint64(0); i < count; i++ {
		slot := be.Uint32(data[12+i*8:])
		off := uint64(be.Uint32(data[16+i*8:]))
		if slots[slot] {
			return nil, errors.New("duplicate signature slot")
		}
		slots[slot] = true
		if off < 12+count*8 || off > length || length-off < 8 {
			return nil, errors.New("invalid blob offset")
		}
		magic, n := be.Uint32(data[off:]), uint64(be.Uint32(data[off+4:]))
		if n < 8 || n > length-off {
			return nil, errors.New("invalid blob length")
		}
		b := data[off : off+n]
		switch {
		case slot == 0 || (slot >= 0x1000 && slot < 0x1005):
			if magic != 0xfade0c02 {
				return nil, errors.New("invalid CodeDirectory magic")
			}
			cd, e := directory(b)
			if e != nil {
				return nil, e
			}
			cd.Slot = slot
			s.Directories = append(s.Directories, cd)
		case slot == 2:
			if magic != 0xfade0c01 {
				return nil, errors.New("invalid requirements magic")
			}
		case slot == 5:
			if magic != 0xfade7171 {
				return nil, errors.New("invalid XML entitlement magic")
			}
			s.HasXML = true
			var e error
			s.Entitlements, e = plist.Decode(bytes.TrimRight(b[8:], "\x00"))
			if e != nil {
				s.EntitlementError = e.Error()
				s.Notes = append(s.Notes, "entitlements unavailable: "+e.Error())
			}
		case slot == 7:
			if magic != 0xfade7172 {
				return nil, errors.New("invalid DER entitlement magic")
			}
			s.HasDER = true
		case slot == 0x10000:
			if magic != 0xfade0b01 {
				return nil, errors.New("invalid CMS magic")
			}
			s.HasCMS = len(b) > 8
			if s.HasCMS {
				var e error
				s.Authorities, e = authorities(b[8:])
				if e != nil {
					s.Notes = append(s.Notes, "signature present; authority chain unavailable: "+e.Error())
				}
			}
		}
	}
	if len(s.Directories) == 0 {
		return nil, errors.New("signature contains no CodeDirectory")
	}
	sort.Slice(s.Directories, func(i, j int) bool { return s.Directories[i].Slot < s.Directories[j].Slot })
	if !s.HasXML && s.HasDER {
		s.EntitlementError = "DER entitlements exist but were not decoded"
		s.Notes = append(s.Notes, s.EntitlementError)
	}
	return s, nil
}
func directory(b []byte) (CodeDirectory, error) {
	c := CodeDirectory{}
	if len(b) < 44 {
		return c, errors.New("truncated CodeDirectory")
	}
	be := binary.BigEndian
	c.Version = be.Uint32(b[8:])
	c.Magic, c.Length = be.Uint32(b), be.Uint32(b[4:])
	c.Flags = be.Uint32(b[12:])
	c.HashOffset, c.IdentOffset = be.Uint32(b[16:]), be.Uint32(b[20:])
	c.SpecialSlots, c.CodeSlots, c.CodeLimit = be.Uint32(b[24:]), be.Uint32(b[28:]), be.Uint32(b[32:])
	c.HashSize, c.HashType, c.Platform, c.PageSize = b[36], b[37], b[38], b[39]
	c.Spare2 = be.Uint32(b[40:])
	min := 44
	if c.Version >= 0x20100 {
		min = 48
	}
	if c.Version >= 0x20200 {
		min = 52
	}
	if len(b) < min {
		return c, errors.New("truncated versioned CodeDirectory")
	}
	if c.Version >= 0x20100 {
		c.ScatterOffset = be.Uint32(b[44:])
	}
	if c.Version >= 0x20200 {
		c.TeamOffset = be.Uint32(b[48:])
	}
	str := func(off uint32) (string, error) {
		if off < uint32(min) || uint64(off) >= uint64(len(b)) {
			return "", errors.New("invalid CodeDirectory string offset")
		}
		tail := b[off:]
		end := bytes.IndexByte(tail, 0)
		if end < 0 {
			return "", errors.New("unterminated CodeDirectory string")
		}
		return string(tail[:end]), nil
	}
	var e error
	c.Identifier, e = str(be.Uint32(b[20:]))
	if e != nil {
		return c, e
	}
	if c.Version >= 0x20200 {
		off := be.Uint32(b[48:])
		if off != 0 {
			c.TeamID, e = str(off)
		}
	}
	return c, e
}
func raw(b []byte) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, e := asn1.Unmarshal(b, &v)
	return v, rest, e
}
func authorities(b []byte) ([]string, error) {
	// ContentInfo -> explicit SignedData -> certificate set. No trust or signature checks.
	normalized, err := normalizeBER(b)
	if err != nil {
		return nil, err
	}
	b = normalized
	outer, _, e := raw(b)
	if e != nil || outer.Tag != 16 {
		return nil, errors.New("invalid CMS ContentInfo")
	}
	var oid asn1.ObjectIdentifier
	rest, e := asn1.Unmarshal(outer.Bytes, &oid)
	if e != nil || !oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return nil, errors.New("CMS is not SignedData")
	}
	explicit, _, e := raw(rest)
	if e != nil || explicit.Class != 2 || explicit.Tag != 0 {
		return nil, errors.New("missing SignedData")
	}
	seq, _, e := raw(explicit.Bytes)
	if e != nil || seq.Tag != 16 {
		return nil, errors.New("invalid SignedData")
	}
	rest = seq.Bytes
	for i := 0; i < 3; i++ {
		_, rest, e = raw(rest)
		if e != nil {
			return nil, e
		}
	}
	certset, _, e := raw(rest)
	if e != nil || certset.Class != 2 || certset.Tag != 0 {
		return nil, errors.New("missing certificates")
	}
	certs := []*x509.Certificate{}
	rest = certset.Bytes
	for len(rest) > 0 {
		if len(certs) >= 128 {
			return nil, errors.New("certificate count cap")
		}
		var cert asn1.RawValue
		cert, rest, e = raw(rest)
		if e != nil {
			return nil, e
		}
		c, e := x509.ParseCertificate(cert.FullBytes)
		if e != nil {
			return nil, e
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("empty certificate set")
	}
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i].Raw, certs[j].Raw) < 0 })
	leaf := -1
	for i, c := range certs {
		issuer := false
		for j, other := range certs {
			if i != j && bytes.Equal(c.RawSubject, other.RawIssuer) {
				issuer = true
			}
		}
		if !issuer {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		return nil, errors.New("certificate issuer cycle")
	}
	names := []string{}
	seen := map[int]bool{}
	for leaf >= 0 && !seen[leaf] {
		seen[leaf] = true
		c := certs[leaf]
		names = append(names, c.Subject.CommonName)
		next := -1
		if !bytes.Equal(c.RawIssuer, c.RawSubject) {
			for i, parent := range certs {
				if !seen[i] && bytes.Equal(c.RawIssuer, parent.RawSubject) {
					next = i
					break
				}
			}
		}
		leaf = next
	}
	return names, nil
}
