package macho

import (
	"errors"
	"github.com/harinaralasetty/underhood/internal/model"
)

// normalizeBER converts bounded constructed indefinite lengths used by CMS to DER lengths.
// Primitive payloads, including certificate bytes, are preserved.
func normalizeBER(b []byte) ([]byte, error) {
	nodes := 0
	out, used, e := berElement(b, 0, &nodes)
	if e != nil {
		return nil, e
	}
	if used != len(b) {
		return nil, errors.New("trailing CMS bytes")
	}
	return out, nil
}
func berElement(b []byte, depth int, nodes *int) ([]byte, int, error) {
	*nodes++
	if depth >= 64 || *nodes > 200000 || len(b) < 2 || len(b) > model.MaxMetadata {
		return nil, 0, errors.New("invalid or excessive BER")
	}
	tagEnd := 1
	if b[0]&31 == 31 {
		for {
			if tagEnd >= len(b) || tagEnd > 8 {
				return nil, 0, errors.New("invalid BER tag")
			}
			v := b[tagEnd]
			tagEnd++
			if v&128 == 0 {
				break
			}
		}
	}
	if tagEnd >= len(b) {
		return nil, 0, errors.New("missing BER length")
	}
	pos := tagEnd + 1
	size := int(b[tagEnd])
	indefinite := size == 128
	if size > 128 {
		n := size & 127
		if n > 4 || len(b)-pos < n {
			return nil, 0, errors.New("invalid BER length")
		}
		size = 0
		for _, v := range b[pos : pos+n] {
			size = size<<8 | int(v)
		}
		pos += n
	}
	if indefinite && b[0]&32 == 0 {
		return nil, 0, errors.New("indefinite primitive BER")
	}
	if !indefinite && (size < 0 || size > len(b)-pos) {
		return nil, 0, errors.New("truncated BER")
	}
	var body []byte
	used := pos
	if b[0]&32 != 0 {
		end := len(b)
		if !indefinite {
			end = pos + size
		}
		for used < end {
			if indefinite && len(b)-used >= 2 && b[used] == 0 && b[used+1] == 0 {
				used += 2
				indefinite = false
				break
			}
			child, n, e := berElement(b[used:end], depth+1, nodes)
			if e != nil {
				return nil, 0, e
			}
			body = append(body, child...)
			used += n
		}
		if indefinite {
			return nil, 0, errors.New("unterminated BER")
		}
	} else {
		body = b[pos : pos+size]
		used = pos + size
	}
	out := append([]byte{}, b[:tagEnd]...)
	if len(body) < 128 {
		out = append(out, byte(len(body)))
	} else {
		var length [4]byte
		n := len(body)
		i := 4
		for n > 0 {
			i--
			length[i] = byte(n)
			n >>= 8
		}
		out = append(out, 0x80|byte(4-i))
		out = append(out, length[i:]...)
	}
	out = append(out, body...)
	return out, used, nil
}
