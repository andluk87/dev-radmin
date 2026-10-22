package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOriginalDLLReader(t *testing.T) {
	data, err := os.ReadFile("testdata/native-tlv.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Synthetic bool `json:"synthetic_only"`
		Cases     []struct {
			Input    string `json:"input_hex"`
			Accepted bool   `json:"accepted"`
			Consumed int    `json:"consumed"`
			Tag      uint32 `json:"tag"`
			Value    string `json:"value_hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Synthetic || len(fixture.Cases) != 10 {
		t.Fatal("missing native evidence")
	}
	for _, c := range fixture.Cases {
		raw, err := hex.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		f, rest, err := ReadField(raw)
		if (err == nil) != c.Accepted {
			t.Fatalf("native acceptance mismatch for %s", c.Input)
		}
		if err != nil {
			continue
		}
		if f.Tag != c.Tag || hex.EncodeToString(f.Value) != c.Value || len(raw)-len(rest) != c.Consumed {
			t.Fatal("native decode mismatch")
		}
		encoded, err := Encode([]Field{f})
		if err != nil || !bytes.Equal(encoded, raw[:c.Consumed]) {
			t.Fatal("native field roundtrip mismatch")
		}
	}
}

func TestRequest(t *testing.T) {
	command := binary.BigEndian.AppendUint32(nil, 20)
	raw, _ := Encode([]Field{{Tag: CommandTag, Value: command}, {Tag: 0x0a000257, Value: []byte("synthetic")}})
	r, err := DecodeRequest(raw)
	if err != nil || r.Command != 20 || len(r.Fields) != 1 || string(r.Fields[0].Value) != "synthetic" {
		t.Fatalf("request decode: %v", err)
	}
	// Caller mutation must not overwrite the parsed result.
	for i := range raw {
		raw[i] = 0
	}
	if string(r.Fields[0].Value) != "synthetic" {
		t.Fatal("aliased request value")
	}
	for _, fields := range [][]Field{
		{{Tag: CommandTag, Value: command}, {Tag: CommandTag, Value: command}},
		{{Tag: CommandTag, Value: []byte{20}}},
		{{Tag: 5, Value: command}},
	} {
		raw, _ := Encode(fields)
		if _, err := DecodeRequest(raw); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestLimitsAndTrailingData(t *testing.T) {
	if _, err := Decode(make([]byte, MaxMessage+1)); err == nil {
		t.Fatal("oversized input")
	}
	field, _ := Encode([]Field{{Tag: 5, Value: []byte{1}}})
	if _, err := Decode(append(field, 1)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := Decode(bytes.Repeat(field, MaxFields+1)); err == nil {
		t.Fatal("too many fields")
	}
	for _, fields := range [][]Field{nil, {{Tag: 1}}, {{Tag: 1, Value: make([]byte, MaxMessage)}}} {
		if _, err := Encode(fields); err == nil {
			t.Fatal("invalid encoding accepted")
		}
	}
	if _, err := DecodeRequest(field); err == nil {
		t.Fatal("wrong outer tag")
	}
	body, _ := Encode([]Field{{Tag: CommandTag, Value: []byte{0, 0, 0, 20}}})
	outer, _ := Encode([]Field{{Tag: 0x1232, Value: body}})
	if _, err := DecodeRequest(outer); err == nil {
		t.Fatal("logical tag incorrectly accepted as a wire wrapper")
	}
	if _, err := DecodeRequest(append(body, 1)); err == nil {
		t.Fatal("trailing byte accepted after command")
	}
}

func TestOriginalDLLWriter(t *testing.T) {
	data, err := os.ReadFile("testdata/native-tlv.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Encoded []struct {
			Tag     uint32 `json:"tag"`
			Value   string `json:"value_hex"`
			Encoded string `json:"encoded_hex"`
		} `json:"encoded"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Encoded) != 3 {
		t.Fatal("missing native writer vectors")
	}
	for _, c := range fixture.Encoded {
		value, err := hex.DecodeString(c.Value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Encode([]Field{{Tag: c.Tag, Value: value}})
		if err != nil || hex.EncodeToString(got) != c.Encoded {
			t.Fatal("native writer mismatch")
		}
	}
}

func TestEncodeRequest(t *testing.T) {
	want := Request{Command: 20, Fields: []Field{{Tag: 0x0a000257, Value: []byte("synthetic")}}}
	raw, err := EncodeRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(raw)
	if err != nil || got.Command != want.Command || len(got.Fields) != 1 || got.Fields[0].Tag != want.Fields[0].Tag || !bytes.Equal(got.Fields[0].Value, want.Fields[0].Value) {
		t.Fatalf("request encode/decode: %v", err)
	}
	if _, err := EncodeRequest(Request{Command: 20, Fields: []Field{{Tag: CommandTag, Value: []byte{0, 0, 0, 21}}}}); err == nil {
		t.Fatal("reserved command override accepted")
	}
	if _, err := EncodeRequest(Request{Fields: make([]Field, MaxFields)}); err == nil {
		t.Fatal("too many request fields accepted")
	}
	if _, err := EncodeRequest(Request{Fields: []Field{{Tag: 1, Value: make([]byte, MaxMessage-8)}}}); err == nil {
		t.Fatal("command plus fields exceeded message limit")
	}
}
