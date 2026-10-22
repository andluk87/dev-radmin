package control

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPacketOpaqueFields(t *testing.T) {
	want := Packet{Type: 0xfedcba98, Fields: []Field{
		{Tag: 0x0a123456, Value: []byte("synthetic")},
		{Tag: 0x0a123456, Value: []byte{0, 1, 2}},
	}}
	raw, err := EncodePacket(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(raw)
	if err != nil || got.Type != want.Type || len(got.Fields) != len(want.Fields) {
		t.Fatalf("packet decode: %v", err)
	}
	for i := range got.Fields {
		if got.Fields[i].Tag != want.Fields[i].Tag || !bytes.Equal(got.Fields[i].Value, want.Fields[i].Value) {
			t.Fatal("opaque field omitted or reordered")
		}
	}
	for i := range raw {
		raw[i] = 0
	}
	if string(got.Fields[0].Value) != "synthetic" {
		t.Fatal("decoded values alias the input buffer")
	}
}

func TestPacketRejectsAmbiguousType(t *testing.T) {
	value := []byte{0, 0, 0, 16}
	for _, fields := range [][]Field{
		{{Tag: PacketTypeTag, Value: value}, {Tag: PacketTypeTag, Value: value}},
		{{Tag: PacketTypeTag, Value: []byte{16}}},
		{{Tag: PacketTypeTag, Value: append(value, 0)}},
		{{Tag: 0x123b, Value: value}},
	} {
		raw, err := Encode(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodePacket(raw); err == nil {
			t.Fatal("accepted missing, duplicate or wrongly sized packet type")
		}
	}
	if _, err := EncodePacket(Packet{Type: 16, Fields: []Field{{Tag: PacketTypeTag, Value: value}}}); err == nil {
		t.Fatal("packet type override accepted")
	}
}

func TestPacketFieldLimitIncludesType(t *testing.T) {
	fields := make([]Field, MaxFields)
	for i := range fields {
		fields[i] = Field{Tag: 0x0a000001, Value: []byte{1}}
	}
	if _, err := EncodePacket(Packet{Type: 16, Fields: fields}); err == nil {
		t.Fatal("packet exceeded field limit")
	}
	raw, err := EncodePacket(Packet{Type: 16, Fields: fields[:MaxFields-1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePacket(raw); err != nil {
		t.Fatalf("maximum allowed field count failed: %v", err)
	}
	if _, err := EncodePacket(Packet{Type: 16, Fields: []Field{{Tag: 1, Value: make([]byte, MaxMessage-8)}}}); err == nil {
		t.Fatal("packet type plus fields exceeded message size")
	}
}

func TestErrorPacketEncoding(t *testing.T) {
	// The envelope is flat: packet type followed by the nested error-code block.
	want := "0000000401000320000000100000000c0000123b00000004010001d212345678"
	raw, err := EncodeError(0x12345678)
	if err != nil || hex.EncodeToString(raw) != want {
		t.Fatalf("unexpected error encoding: %v", err)
	}
	packet, err := DecodePacket(raw)
	if err != nil || packet.Type != PacketError || len(packet.Fields) != 1 || packet.Fields[0].Tag != ErrorDetailsTag {
		t.Fatalf("error packet decode: %v", err)
	}
	fields, err := Decode(packet.Fields[0].Value)
	if err != nil || len(fields) != 1 || fields[0].Tag != ErrorCodeTag || !bytes.Equal(fields[0].Value, []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Fatalf("error details decode: %v", err)
	}
}
