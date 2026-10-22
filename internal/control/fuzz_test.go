package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func seedNativeTLV(f *testing.F) {
	f.Helper()
	data, err := os.ReadFile("testdata/native-tlv.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Input string `json:"input_hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, c := range fixture.Cases {
		raw, err := hex.DecodeString(c.Input)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
}

// Accepted TLV must preserve every input byte through decode/encode. Arbitrary
// length prefixes and truncated headers exercise the parser's failure paths.
func FuzzDecode(f *testing.F) {
	seedNativeTLV(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		fields, err := Decode(input)
		if err != nil {
			return
		}
		encoded, err := Encode(fields)
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("accepted TLV did not preserve the input bytes")
		}
		if len(fields) == 0 || len(fields) > MaxFields || len(encoded) > MaxMessage {
			t.Fatal("accepted TLV exceeded the configured limits")
		}
	})
}

// A request is accepted only when its complete TLV sequence contains one
// four-byte command. Opaque fields retain their original relative order.
func FuzzDecodeRequest(f *testing.F) {
	seedNativeTLV(f)
	command := binary.BigEndian.AppendUint32(nil, 20)
	request, _ := Encode([]Field{{Tag: CommandTag, Value: command}, {Tag: 0x0a000257, Value: []byte("synthetic")}})
	f.Add(request)
	f.Fuzz(func(t *testing.T, input []byte) {
		request, err := DecodeRequest(input)
		if err != nil {
			return
		}
		fields, err := Decode(input)
		if err != nil {
			t.Fatal("request accepted invalid fields")
		}
		commands, other := 0, 0
		for _, field := range fields {
			if field.Tag == CommandTag {
				commands++
				if len(field.Value) != 4 || binary.BigEndian.Uint32(field.Value) != request.Command {
					t.Fatal("request command differs from its encoded value")
				}
				continue
			}
			if other >= len(request.Fields) || field.Tag != request.Fields[other].Tag || !bytes.Equal(field.Value, request.Fields[other].Value) {
				t.Fatal("request omitted or reordered an opaque field")
			}
			other++
		}
		if commands != 1 || other != len(request.Fields) {
			t.Fatal("request accepted an ambiguous command or extra field")
		}
	})
}
