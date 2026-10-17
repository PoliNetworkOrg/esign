package ias

import (
	"errors"
	"fmt"
)

// TLV is one BER-TLV data object.
type TLV struct {
	Tag   uint32
	Value []byte
	// Raw is the whole encoded object: tag, length and value.
	Raw []byte
}

var errTLV = errors.New("malformed BER-TLV")

// ParseTLV reads the first data object of data and returns it with the bytes that follow it.
func ParseTLV(data []byte) (TLV, []byte, error) {
	if len(data) < 2 {
		return TLV{}, nil, errTLV
	}
	i := 0
	tag := uint32(data[i])
	i++
	if data[0]&0x1f == 0x1f {
		for {
			if i >= len(data) || i > 3 {
				return TLV{}, nil, errTLV
			}
			tag = tag<<8 | uint32(data[i])
			i++
			if data[i-1]&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(data) {
		return TLV{}, nil, errTLV
	}
	length := int(data[i])
	i++
	if length > 0x80 {
		n := length - 0x80
		if n > 3 || i+n > len(data) {
			return TLV{}, nil, errTLV
		}
		length = 0
		for _, b := range data[i : i+n] {
			length = length<<8 | int(b)
		}
		i += n
	} else if length == 0x80 {
		return TLV{}, nil, fmt.Errorf("%w: indefinite length", errTLV)
	}
	if length > len(data)-i {
		return TLV{}, nil, fmt.Errorf("%w: length %d exceeds %d bytes", errTLV, length, len(data)-i)
	}
	end := i + length
	return TLV{Tag: tag, Value: data[i:end], Raw: data[:end]}, data[end:], nil
}

// ParseTLVs reads all the data objects in data.
func ParseTLVs(data []byte) ([]TLV, error) {
	var out []TLV
	for len(data) > 0 {
		t, rest, err := ParseTLV(data)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		data = rest
	}
	return out, nil
}

// Find returns the first object with tag among objs.
func Find(objs []TLV, tag uint32) (TLV, bool) {
	for _, o := range objs {
		if o.Tag == tag {
			return o, true
		}
	}
	return TLV{}, false
}

// Path descends from data through the first child at each level, like the reference's tags[0]->tags[0]...: the
// returned object is the first child after len(levels) descents, and levels name the expected tags (0 accepts any).
func Path(data []byte, levels ...uint32) (TLV, error) {
	cur := data
	var t TLV
	for _, want := range levels {
		var err error
		t, _, err = ParseTLV(cur)
		if err != nil {
			return TLV{}, err
		}
		if want != 0 && t.Tag != want {
			return TLV{}, fmt.Errorf("%w: tag %X, want %X", errTLV, t.Tag, want)
		}
		cur = t.Value
	}
	return t, nil
}

// EncodeTLV encodes one data object with a definite length.
func EncodeTLV(tag uint32, value []byte) []byte {
	var out []byte
	switch {
	case tag > 0xffffff:
		out = append(out, byte(tag>>24), byte(tag>>16), byte(tag>>8), byte(tag))
	case tag > 0xffff:
		out = append(out, byte(tag>>16), byte(tag>>8), byte(tag))
	case tag > 0xff:
		out = append(out, byte(tag>>8), byte(tag))
	default:
		out = append(out, byte(tag))
	}
	n := len(value)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, value...)
}

// EncodedLength is the length of the first BER object in data, used to drop the padding after a certificate or key
// in a fixed-size file.
func EncodedLength(data []byte) (int, error) {
	t, _, err := ParseTLV(data)
	if err != nil {
		return 0, err
	}
	return len(t.Raw), nil
}
