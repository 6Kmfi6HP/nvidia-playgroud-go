// Minimal msgpack codec for the getcaptcha encrypted exchange.
//
// The widget wraps getcaptcha submissions as
//
//	msgpack([ <spec JSON string>, ext(18, <wasm-encrypted params>) ])
//
// and the server answers with a msgpack payload decrypted by the same wasm
// (hsw mode 0). Only the shapes actually exchanged are implemented:
// maps with string keys, strings, arrays, scalars, bin and ext members.
package hcaptcha

import (
	"encoding/binary"
	"fmt"
	"math"
)

// msgpackExtCrypto is the msgpack extension type msgpack-lite uses for
// Uint8Array/ArrayBuffer values; the hCaptcha wire uses it for the encrypted
// payload.
const msgpackExtCrypto = 18

// msgpackEncodeMapString encodes a flat string map (the getcaptcha params).
func msgpackEncodeMapString(m map[string]string) []byte {
	// Build entries, then prefix the map header (fixmap for <16 keys).
	body := []byte{}
	for k, v := range m {
		body = append(body, msgpackEncodeString(k)...)
		body = append(body, msgpackEncodeString(v)...)
	}
	head := []byte{}
	switch {
	case len(m) < 16:
		head = append(head, 0x80|byte(len(m)))
	case len(m) <= 65535:
		head = append(head, 0xde)
		head = binary.BigEndian.AppendUint16(head, uint16(len(m)))
	default:
		head = append(head, 0xdf)
		head = binary.BigEndian.AppendUint32(head, uint32(len(m)))
	}
	return append(head, body...)
}

func msgpackEncodeString(s string) []byte {
	switch {
	case len(s) < 32:
		return append([]byte{0xa0 | byte(len(s))}, s...)
	case len(s) <= math.MaxUint8:
		return append([]byte{0xd9, byte(len(s))}, s...)
	case len(s) <= math.MaxUint16:
		out := []byte{0xda}
		out = binary.BigEndian.AppendUint16(out, uint16(len(s)))
		return append(out, s...)
	default:
		out := []byte{0xdb}
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		return append(out, s...)
	}
}

// msgpackEncodeWire builds [spec, ext18(cipher)] with the exact layout the
// widget sends (str16 spec followed by ext16/ext32 type-18 ciphertext).
func msgpackEncodeWire(spec string, cipher []byte) []byte {
	out := []byte{0x92} // array(2)
	out = append(out, msgpackEncodeString(spec)...)
	switch {
	case len(cipher) <= math.MaxUint8:
		out = append(out, 0xc7, byte(len(cipher)), msgpackExtCrypto)
	case len(cipher) <= math.MaxUint16:
		out = append(out, 0xc8) // ext16
		out = binary.BigEndian.AppendUint16(out, uint16(len(cipher)))
		out = append(out, msgpackExtCrypto)
	default:
		out = append(out, 0xc9) // ext32
		out = binary.BigEndian.AppendUint32(out, uint32(len(cipher)))
		out = append(out, msgpackExtCrypto)
	}
	return append(out, cipher...)
}

// msgpackDecode parses one msgpack value (map/array/scalar). Ext and bin
// members come back as []byte; ints as int64, uints as uint64, floats as
// float64. Returns the remaining bytes too for top-level validation.
func msgpackDecode(b []byte) (any, []byte, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("msgpack: empty input")
	}
	tag := b[0]
	switch {
	case tag <= 0x7f:
		return int64(tag), b[1:], nil
	case tag >= 0xe0:
		return int64(int8(tag)), b[1:], nil
	case tag >= 0x80 && tag <= 0x8f: // fixmap
		n := int(tag & 0x0f)
		rest := b[1:]
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			k, r, err := msgpackDecode(rest)
			if err != nil {
				return nil, nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, nil, fmt.Errorf("msgpack: map key is %T, want string", k)
			}
			v, r2, err := msgpackDecode(r)
			if err != nil {
				return nil, nil, err
			}
			m[ks] = v
			rest = r2
		}
		return m, rest, nil
	case tag == 0xde, tag == 0xdf: // map16/map32
		var n int
		var rest []byte
		if tag == 0xde {
			if len(b) < 3 {
				return nil, nil, fmt.Errorf("msgpack: truncated map16")
			}
			n = int(binary.BigEndian.Uint16(b[1:3]))
			rest = b[3:]
		} else {
			if len(b) < 5 {
				return nil, nil, fmt.Errorf("msgpack: truncated map32")
			}
			n = int(binary.BigEndian.Uint32(b[1:5]))
			rest = b[5:]
		}
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			k, r, err := msgpackDecode(rest)
			if err != nil {
				return nil, nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, nil, fmt.Errorf("msgpack: map key is %T, want string", k)
			}
			v, r2, err := msgpackDecode(r)
			if err != nil {
				return nil, nil, err
			}
			m[ks] = v
			rest = r2
		}
		return m, rest, nil
	case tag >= 0x90 && tag <= 0x9f: // fixarray
		n := int(tag & 0x0f)
		return msgpackDecodeArray(b[1:], n)
	case tag == 0xdc, tag == 0xdd: // array16/array32
		var n int
		var rest []byte
		if tag == 0xdc {
			if len(b) < 3 {
				return nil, nil, fmt.Errorf("msgpack: truncated array16")
			}
			n = int(binary.BigEndian.Uint16(b[1:3]))
			rest = b[3:]
		} else {
			if len(b) < 5 {
				return nil, nil, fmt.Errorf("msgpack: truncated array32")
			}
			n = int(binary.BigEndian.Uint32(b[1:5]))
			rest = b[5:]
		}
		return msgpackDecodeArray(rest, n)
	case tag >= 0xa0 && tag <= 0xbf: // fixstr
		n := int(tag & 0x1f)
		if len(b) < 1+n {
			return nil, nil, fmt.Errorf("msgpack: truncated fixstr")
		}
		return string(b[1 : 1+n]), b[1+n:], nil
	case tag == 0xd9, tag == 0xda, tag == 0xdb: // str8/16/32
		return msgpackDecodeStr(b)
	case tag == 0xc4, tag == 0xc5, tag == 0xc6: // bin8/16/32
		ln, rest, err := msgpackLen(b, 1)
		if err != nil {
			return nil, nil, err
		}
		return append([]byte(nil), rest[:ln]...), rest[ln:], nil
	case tag == 0xc7, tag == 0xc8, tag == 0xc9: // ext8/16/32
		ln, rest, err := msgpackLen(b, 1)
		if err != nil {
			return nil, nil, err
		}
		if len(rest) < 1 {
			return nil, nil, fmt.Errorf("msgpack: truncated ext type")
		}
		payload := rest[1 : 1+ln]
		return append([]byte(nil), payload...), rest[1+ln:], nil
	case tag >= 0xd4 && tag <= 0xd8: // fixext 1/2/4/8/16
		ln := 1 << (tag - 0xd4)
		if len(b) < 1+1+ln {
			return nil, nil, fmt.Errorf("msgpack: truncated fixext")
		}
		return append([]byte(nil), b[2:2+ln]...), b[2+ln:], nil
	case tag == 0xc0:
		return nil, b[1:], nil
	case tag == 0xc2:
		return false, b[1:], nil
	case tag == 0xc3:
		return true, b[1:], nil
	case tag == 0xcc, tag == 0xcd, tag == 0xce, tag == 0xcf: // uint
		return msgpackDecodeUint(b)
	case tag == 0xd0, tag == 0xd1, tag == 0xd2, tag == 0xd3: // int
		return msgpackDecodeInt(b)
	case tag == 0xca, tag == 0xcb: // float32/64
		return msgpackDecodeFloat(b)
	case tag == 0xc1:
		return nil, nil, fmt.Errorf("msgpack: reserved tag 0xc1")
	default:
		return nil, nil, fmt.Errorf("msgpack: unsupported tag %#x", tag)
	}
}

func msgpackDecodeArray(rest []byte, n int) (any, []byte, error) {
	arr := make([]any, 0, n)
	for i := 0; i < n; i++ {
		v, r, err := msgpackDecode(rest)
		if err != nil {
			return nil, nil, err
		}
		arr = append(arr, v)
		rest = r
	}
	return arr, rest, nil
}

func msgpackDecodeStr(b []byte) (any, []byte, error) {
	ln, rest, err := msgpackLen(b, 1)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) < ln {
		return nil, nil, fmt.Errorf("msgpack: truncated str")
	}
	return string(rest[:ln]), rest[ln:], nil
}

func msgpackDecodeUint(b []byte) (any, []byte, error) {
	var n uint64
	var rest []byte
	switch b[0] {
	case 0xcc:
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("msgpack: truncated uint8")
		}
		n, rest = uint64(b[1]), b[2:]
	case 0xcd:
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: truncated uint16")
		}
		n, rest = uint64(binary.BigEndian.Uint16(b[1:3])), b[3:]
	case 0xce:
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: truncated uint32")
		}
		n, rest = uint64(binary.BigEndian.Uint32(b[1:5])), b[5:]
	case 0xcf:
		if len(b) < 9 {
			return nil, nil, fmt.Errorf("msgpack: truncated uint64")
		}
		n, rest = binary.BigEndian.Uint64(b[1:9]), b[9:]
	}
	return n, rest, nil
}

func msgpackDecodeInt(b []byte) (any, []byte, error) {
	var n int64
	var rest []byte
	switch b[0] {
	case 0xd0:
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("msgpack: truncated int8")
		}
		n, rest = int64(int8(b[1])), b[2:]
	case 0xd1:
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: truncated int16")
		}
		n, rest = int64(int16(binary.BigEndian.Uint16(b[1:3]))), b[3:]
	case 0xd2:
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: truncated int32")
		}
		n, rest = int64(int32(binary.BigEndian.Uint32(b[1:5]))), b[5:]
	case 0xd3:
		if len(b) < 9 {
			return nil, nil, fmt.Errorf("msgpack: truncated int64")
		}
		n, rest = int64(binary.BigEndian.Uint64(b[1:9])), b[9:]
	}
	return n, rest, nil
}

func msgpackDecodeFloat(b []byte) (any, []byte, error) {
	switch b[0] {
	case 0xca:
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: truncated float32")
		}
		v := math.Float32frombits(binary.BigEndian.Uint32(b[1:5]))
		return float64(v), b[5:], nil
	case 0xcb:
		if len(b) < 9 {
			return nil, nil, fmt.Errorf("msgpack: truncated float64")
		}
		v := math.Float64frombits(binary.BigEndian.Uint64(b[1:9]))
		return v, b[9:], nil
	}
	return nil, nil, fmt.Errorf("msgpack: not a float")
}

// msgpackLen reads a length prefix after the tag at b[0]; width selects the
// field size (1 = 8-bit/16-bit/32-bit based on tag).
func msgpackLen(b []byte, width int) (int, []byte, error) {
	switch b[0] {
	case 0xd9, 0xc4, 0xc7:
		if len(b) < 2 {
			return 0, nil, fmt.Errorf("msgpack: truncated length")
		}
		return int(b[1]), b[2:], nil
	case 0xda, 0xc5, 0xc8:
		if len(b) < 3 {
			return 0, nil, fmt.Errorf("msgpack: truncated length")
		}
		return int(binary.BigEndian.Uint16(b[1:3])), b[3:], nil
	case 0xdb, 0xc6, 0xc9:
		if len(b) < 5 {
			return 0, nil, fmt.Errorf("msgpack: truncated length")
		}
		return int(binary.BigEndian.Uint32(b[1:5])), b[5:], nil
	}
	return 0, nil, fmt.Errorf("msgpack: tag %#x has no length", b[0])
}
