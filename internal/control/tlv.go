// Package control implements the observed ROS TLV envelope, not VPN operations.
package control

import (
	"encoding/binary"
	"errors"
)

const (
	MaxMessage        = 1 << 20
	MaxFields         = 1024
	CommandTag uint32 = 0x0100031f
)

var ErrMessage = errors.New("invalid or oversized control message")

// Field preserves unknown tags and opaque values. Decoding copies values.
type Field struct {
	Tag   uint32
	Value []byte
}

// ReadField reads one field and returns the unconsumed suffix. Native fields
// have a nonzero value length; the length excludes the eight-byte header.
func ReadField(data []byte) (Field, []byte, error) {
	if len(data) < 8 || len(data) > MaxMessage {
		return Field{}, nil, ErrMessage
	}
	n := binary.BigEndian.Uint32(data)
	if n == 0 || uint64(n) > uint64(len(data)-8) {
		return Field{}, nil, ErrMessage
	}
	end := 8 + int(n)
	return Field{Tag: binary.BigEndian.Uint32(data[4:8]), Value: append([]byte(nil), data[8:end]...)}, data[end:], nil
}

// Decode requires every byte to belong to a complete field. It does not recurse
// into unknown values, so nesting cannot cause unbounded parser recursion.
func Decode(data []byte) ([]Field, error) {
	if len(data) == 0 || len(data) > MaxMessage {
		return nil, ErrMessage
	}
	var fields []Field
	for len(data) > 0 {
		if len(fields) == MaxFields {
			return nil, ErrMessage
		}
		f, rest, err := ReadField(data)
		if err != nil {
			return nil, err
		}
		fields = append(fields, f)
		data = rest
	}
	return fields, nil
}

func Encode(fields []Field) ([]byte, error) {
	if len(fields) == 0 || len(fields) > MaxFields {
		return nil, ErrMessage
	}
	size := 0
	for _, f := range fields {
		if len(f.Value) == 0 || len(f.Value) > MaxMessage-8 || size > MaxMessage-8-len(f.Value) {
			return nil, ErrMessage
		}
		size += 8 + len(f.Value)
	}
	out := make([]byte, 0, size)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f.Value)))
		out = binary.BigEndian.AppendUint32(out, f.Tag)
		out = append(out, f.Value...)
	}
	return out, nil
}

// Request is the serialized request body: a TLV sequence with exactly one
// uint32 command field. Other fields are retained without interpretation.
// The native builder's logical 0x1232 tag is not an on-wire wrapper.
type Request struct {
	Command uint32
	Fields  []Field
}

func DecodeRequest(data []byte) (Request, error) {
	fields, err := Decode(data)
	if err != nil {
		return Request{}, err
	}
	var result Request
	found := false
	for _, f := range fields {
		if f.Tag == CommandTag {
			if found || len(f.Value) != 4 {
				return Request{}, ErrMessage
			}
			result.Command = binary.BigEndian.Uint32(f.Value)
			found = true
		} else {
			result.Fields = append(result.Fields, f)
		}
	}
	if !found {
		return Request{}, ErrMessage
	}
	return result, nil
}

// EncodeRequest writes the command followed by the opaque fields. Callers cannot
// override the command by adding a second reserved command field.
func EncodeRequest(request Request) ([]byte, error) {
	if len(request.Fields) >= MaxFields {
		return nil, ErrMessage
	}
	for _, field := range request.Fields {
		if field.Tag == CommandTag {
			return nil, ErrMessage
		}
	}
	fields := make([]Field, 0, len(request.Fields)+1)
	fields = append(fields, Field{Tag: CommandTag, Value: binary.BigEndian.AppendUint32(nil, request.Command)})
	fields = append(fields, request.Fields...)
	return Encode(fields)
}
