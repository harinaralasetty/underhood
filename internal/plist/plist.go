// Package plist decodes bounded XML and binary property lists without external tools.
package plist

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/harinaralasetty/underhood/internal/model"
)

const maxNodes = 200000
const maxDepth = 64

// Decode requires a dictionary root and rejects malformed or excessive input.
func Decode(data []byte) (map[string]any, error) {
	if len(data) > model.MaxMetadata {
		return nil, errors.New("metadata cap of 16 MiB reached")
	}
	var v any
	var err error
	if bytes.HasPrefix(data, []byte("bplist00")) {
		v, err = decodeBinary(data)
	} else {
		v, err = decodeXML(data)
	}
	if err != nil {
		return nil, err
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("plist root is not a dictionary")
	}
	return d, nil
}
func decodeXML(b []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	nodes := 0
	for {
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		if s, ok := t.(xml.StartElement); ok {
			if s.Name.Local != "plist" {
				return nil, errors.New("missing plist element")
			}
			t, e = next(d)
			if e != nil {
				return nil, e
			}
			start, ok := t.(xml.StartElement)
			if !ok {
				return nil, errors.New("missing plist value")
			}
			v, e := xmlValue(d, start, 0, &nodes)
			if e != nil {
				return nil, e
			}
			t, e = next(d)
			if e != nil {
				return nil, e
			}
			end, ok := t.(xml.EndElement)
			if !ok || end.Name.Local != "plist" {
				return nil, errors.New("invalid plist end")
			}
			_, e = next(d)
			if e != io.EOF {
				return nil, errors.New("trailing plist content")
			}
			return v, nil
		}
	}
}
func next(d *xml.Decoder) (xml.Token, error) {
	for {
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch v := t.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(v)) != "" {
				return nil, errors.New("unexpected plist text")
			}
		case xml.Comment, xml.ProcInst:
		case xml.Directive:
			if bytes.Contains(bytes.ToUpper(v), []byte("ENTITY")) {
				return nil, errors.New("entity declarations not supported")
			}
		default:
			return t, nil
		}
	}
}
func xmlValue(d *xml.Decoder, s xml.StartElement, depth int, nodes *int) (any, error) {
	*nodes++
	if depth >= maxDepth || *nodes > maxNodes {
		return nil, errors.New("plist recursion/size cap reached")
	}
	if s.Name.Local == "dict" || s.Name.Local == "array" {
		dict := map[string]any{}
		array := []any{}
		for {
			t, e := next(d)
			if e != nil {
				return nil, e
			}
			if end, ok := t.(xml.EndElement); ok {
				if end.Name != s.Name {
					return nil, errors.New("mismatched plist element")
				}
				if s.Name.Local == "dict" {
					return dict, nil
				}
				return array, nil
			}
			child, ok := t.(xml.StartElement)
			if !ok {
				return nil, errors.New("invalid plist child")
			}
			key := ""
			if s.Name.Local == "dict" {
				if child.Name.Local != "key" {
					return nil, errors.New("dictionary key expected")
				}
				if e = d.DecodeElement(&key, &child); e != nil {
					return nil, e
				}
				t, e = next(d)
				if e != nil {
					return nil, e
				}
				child, ok = t.(xml.StartElement)
				if !ok {
					return nil, errors.New("dictionary value expected")
				}
				if _, exists := dict[key]; exists {
					return nil, errors.New("duplicate dictionary key")
				}
			}
			v, e := xmlValue(d, child, depth+1, nodes)
			if e != nil {
				return nil, e
			}
			if s.Name.Local == "dict" {
				dict[key] = v
			} else {
				array = append(array, v)
			}
		}
	}
	var text string
	if e := d.DecodeElement(&text, &s); e != nil {
		return nil, e
	}
	trim := strings.TrimSpace(text)
	switch s.Name.Local {
	case "string":
		return text, nil
	case "true", "false":
		if trim != "" {
			return nil, errors.New("invalid boolean")
		}
		return s.Name.Local == "true", nil
	case "integer":
		v, e := strconv.ParseInt(trim, 0, 64)
		if e != nil {
			v, e = strconv.ParseInt(trim, 10, 64)
		}
		if e != nil && !strings.HasPrefix(trim, "-") {
			u, ue := strconv.ParseUint(trim, 10, 64)
			return u, ue
		}
		return v, e
	case "real":
		v, e := strconv.ParseFloat(trim, 64)
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return nil, errors.New("non-finite real")
		}
		return v, e
	case "date":
		return time.Parse(time.RFC3339, trim)
	case "data":
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(trim), ""))
	}
	return nil, fmt.Errorf("unsupported plist element %q", s.Name.Local)
}

type binaryDecoder struct {
	data    []byte
	offsets []uint64
	refSize int
	end     uint64
	active  map[uint64]bool
	nodes   int
	decoded uint64
}

func uintN(b []byte) (uint64, error) {
	if len(b) < 1 || len(b) > 8 {
		return 0, errors.New("invalid integer width")
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}
func decodeBinary(b []byte) (any, error) {
	if len(b) < 40 {
		return nil, errors.New("truncated binary plist")
	}
	t := b[len(b)-32:]
	osz, rsz := int(t[6]), int(t[7])
	count := binary.BigEndian.Uint64(t[8:16])
	root := binary.BigEndian.Uint64(t[16:24])
	off := binary.BigEndian.Uint64(t[24:32])
	if osz < 1 || osz > 8 || rsz < 1 || rsz > 8 || count == 0 || count > maxNodes || root >= count || off < 8 || off > uint64(len(b)-32) || count > uint64(len(b)-32-int(off))/uint64(osz) {
		return nil, errors.New("invalid binary plist trailer")
	}
	p := binaryDecoder{data: b, refSize: rsz, end: off, active: map[uint64]bool{}}
	for i := uint64(0); i < count; i++ {
		v, _ := uintN(b[off+i*uint64(osz) : off+(i+1)*uint64(osz)])
		if v < 8 || v >= off {
			return nil, errors.New("invalid object offset")
		}
		p.offsets = append(p.offsets, v)
	}
	return p.object(root, 0)
}
func (p *binaryDecoder) span(off, n uint64) ([]byte, error) {
	if n > 4*model.MaxMetadata-p.decoded {
		return nil, errors.New("decoded plist size cap of 64 MiB reached")
	}
	p.decoded += n
	if off > p.end || n > p.end-off {
		return nil, errors.New("truncated binary plist object")
	}
	return p.data[off : off+n], nil
}
func (p *binaryDecoder) object(id uint64, depth int) (any, error) {
	p.nodes++
	if depth >= maxDepth || p.nodes > maxNodes || id >= uint64(len(p.offsets)) || p.active[id] {
		return nil, errors.New("invalid reference or plist recursion/size cap reached")
	}
	p.active[id] = true
	defer delete(p.active, id)
	pos := p.offsets[id]
	tag := p.data[pos]
	pos++
	kind, lo := tag>>4, uint64(tag&15)
	n := lo
	if kind >= 4 && kind != 8 && lo == 15 {
		b, e := p.span(pos, 1)
		if e != nil {
			return nil, e
		}
		if b[0]>>4 != 1 || b[0]&15 > 3 {
			return nil, errors.New("invalid object length")
		}
		width := uint64(1) << uint(b[0]&15)
		b, e = p.span(pos+1, width)
		if e != nil {
			return nil, e
		}
		n, _ = uintN(b)
		pos += 1 + width
	}
	switch kind {
	case 0:
		switch lo {
		case 0:
			return nil, nil
		case 8:
			return false, nil
		case 9:
			return true, nil
		}
	case 1:
		if lo > 4 {
			return nil, errors.New("integer exceeds 128 bits")
		}
		b, e := p.span(pos, 1<<lo)
		if e != nil {
			return nil, e
		}
		if len(b) == 16 {
			v := new(big.Int).SetBytes(b)
			if b[0]&128 != 0 {
				v.Sub(v, new(big.Int).Lsh(big.NewInt(1), 128))
			}
			return json.Number(v.String()), nil
		}
		v, _ := uintN(b)
		return int64(v), nil
	case 2:
		if lo != 2 && lo != 3 {
			return nil, errors.New("invalid real width")
		}
		b, e := p.span(pos, 1<<lo)
		if e != nil {
			return nil, e
		}
		var v float64
		if lo == 2 {
			v = float64(math.Float32frombits(binary.BigEndian.Uint32(b)))
		} else {
			v = math.Float64frombits(binary.BigEndian.Uint64(b))
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, errors.New("non-finite real")
		}
		return v, nil
	case 3:
		if lo != 3 {
			return nil, errors.New("invalid date")
		}
		b, e := p.span(pos, 8)
		if e != nil {
			return nil, e
		}
		v := math.Float64frombits(binary.BigEndian.Uint64(b))
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e11 {
			return nil, errors.New("date out of range")
		}
		sec, frac := math.Modf(v)
		return time.Unix(978307200+int64(sec), int64(frac*1e9)).UTC(), nil
	case 4, 5, 6:
		width := uint64(1)
		if kind == 6 {
			width = 2
		}
		if n > uint64(model.MaxMetadata)/width {
			return nil, errors.New("object size cap reached")
		}
		b, e := p.span(pos, n*width)
		if e != nil {
			return nil, e
		}
		if kind == 4 {
			return append([]byte(nil), b...), nil
		}
		if kind == 5 {
			return string(b), nil
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[i*2:])
		}
		return string(utf16.Decode(u)), nil
	case 8:
		b, e := p.span(pos, lo+1)
		if e != nil {
			return nil, e
		}
		v, e := uintN(b)
		return map[string]any{"CF$UID": v}, e
	case 10, 11, 12, 13:
		mul := uint64(1)
		if kind == 13 {
			mul = 2
		}
		if n > maxNodes {
			return nil, errors.New("container size cap reached")
		}
		b, e := p.span(pos, n*mul*uint64(p.refSize))
		if e != nil {
			return nil, e
		}
		ref := func(i uint64) uint64 { v, _ := uintN(b[i*uint64(p.refSize) : (i+1)*uint64(p.refSize)]); return v }
		a := make([]any, 0, n)
		d := map[string]any{}
		for i := uint64(0); i < n; i++ {
			v, e := p.object(ref(i), depth+1)
			if e != nil {
				return nil, e
			}
			if kind == 13 {
				k, ok := v.(string)
				if !ok {
					return nil, errors.New("non-string dictionary key")
				}
				if _, exists := d[k]; exists {
					return nil, errors.New("duplicate dictionary key")
				}
				v, e = p.object(ref(i+n), depth+1)
				if e != nil {
					return nil, e
				}
				d[k] = v
			} else {
				a = append(a, v)
			}
		}
		if kind == 13 {
			return d, nil
		}
		return a, nil
	}
	return nil, fmt.Errorf("unsupported binary plist tag 0x%x", tag)
}
