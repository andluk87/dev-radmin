package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIsAliveWireShapes(t *testing.T) {
	const nonce = uint64(0x1122334455667788)
	for _, tc := range []struct {
		name   string
		encode func(uint64) []byte
		decode func([]byte) (uint64, error)
		hex    string
	}{
		{"server", EncodeIsAlive, DecodeIsAlive, "000000040100032000000012000000100000126700000008020002321122334455667788"},
		{"client", EncodeIsAliveReply, DecodeIsAliveReply, "000000240000123c00000004010001d40000001b000000100000126700000008020002321122334455667788"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.encode(nonce)
			if hex.EncodeToString(data) != tc.hex {
				t.Fatal("wire shape mismatch")
			}
			got, err := tc.decode(data)
			if err != nil || got != nonce {
				t.Fatalf("nonce mismatch: %x %v", got, err)
			}
			for _, n := range []uint64{0, 1, ^uint64(0)} {
				got, err := tc.decode(tc.encode(n))
				if err != nil || got != n {
					t.Fatal("nonce bits lost")
				}
			}
			for i := 0; i < len(data); i++ {
				if _, err := tc.decode(data[:i]); err == nil {
					t.Fatalf("truncation %d accepted", i)
				}
			}
			if _, err := tc.decode(append(data, 1)); err == nil {
				t.Fatal("trailing data accepted")
			}
		})
	}
}

func TestIsAliveRejectsAmbiguousNonce(t *testing.T) {
	probe := EncodeIsAlive(42)
	fields, err := Decode(probe)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]Field{
		{fields[0]},
		{fields[1]},
		{fields[0], fields[0], fields[1]},
		{fields[0], fields[1], fields[1]},
		{fields[0], {Tag: isAliveContainerTag, Value: append(isAliveField(isAliveNonceTag, make([]byte, 8)), isAliveField(isAliveNonceTag, make([]byte, 8))...)}},
		{fields[0], {Tag: isAliveContainerTag, Value: isAliveField(isAliveNonceTag, []byte{1})}},
		{{Tag: isAlivePacketTypeTag, Value: binary.BigEndian.AppendUint32(nil, 17)}, fields[1]},
		{{Tag: isAlivePacketTypeTag, Value: []byte{18}}, fields[1]},
	} {
		raw, err := Encode(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeIsAlive(raw); err == nil {
			t.Fatal("ambiguous or malformed probe accepted")
		}
	}
	// Unknown complete fields do not change the required nonce.
	extended := append(append([]byte(nil), probe...), isAliveField(0x0a00ffff, []byte("opaque"))...)
	if n, err := DecodeIsAlive(extended); err != nil || n != 42 {
		t.Fatal("unknown field rejected")
	}
	if _, err := DecodeIsAliveReply(probe); err == nil {
		t.Fatal("server probe accepted as client reply")
	}
	if _, err := DecodeIsAlive(EncodeIsAliveReply(42)); err == nil {
		t.Fatal("client reply accepted as server probe")
	}
}

func TestIsAliveReplyRequiresOpcode27(t *testing.T) {
	reply := EncodeIsAliveReply(42)
	fields, err := Decode(reply)
	if err != nil {
		t.Fatal(err)
	}
	for _, head := range [][]byte{
		isAliveField(isAliveOpcodeTag, []byte{27}),
		isAliveField(isAliveOpcodeTag, binary.BigEndian.AppendUint32(nil, 26)),
		append(isAliveField(isAliveOpcodeTag, []byte{0, 0, 0, 27}), isAliveField(isAliveOpcodeTag, []byte{0, 0, 0, 27})...),
		isAliveField(CommandTag, []byte{0, 0, 0, 27}),
	} {
		bad := []Field{{Tag: isAliveHeaderTag, Value: append(head, isAliveNonce(42)...)}}
		raw, err := Encode(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeIsAliveReply(raw); err == nil {
			t.Fatal("bad client opcode accepted")
		}
	}
	duplicate := append(append([]byte(nil), reply...), isAliveField(isAliveHeaderTag, fields[0].Value)...)
	if _, err := DecodeIsAliveReply(duplicate); err == nil {
		t.Fatal("duplicate header accepted")
	}
	if bytes.Equal(reply, EncodeIsAlive(42)) {
		t.Fatal("request and reply confused")
	}
}

func TestIsAliveMatchesOriginalDecoder(t *testing.T) {
	data, err := os.ReadFile("testdata/native-responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Synthetic bool `json:"synthetic_only"`
		Cases     []struct {
			Kind     string `json:"kind"`
			Input    string `json:"input_hex"`
			Accepted bool   `json:"accepted"`
			Nonce    uint64 `json:"nonce"`
		} `json:"cases"`
		Factory []struct {
			Input      string `json:"input_hex"`
			PacketType uint32 `json:"packet_type"`
			Nonce      uint64 `json:"nonce"`
		} `json:"factory"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Synthetic {
		t.Fatal("missing synthetic native evidence")
	}
	cases := 0
	for _, c := range fixture.Cases {
		if c.Kind != "is_alive" {
			continue
		}
		cases++
		raw, err := hex.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := DecodeIsAlive(raw)
		if (err == nil) != c.Accepted {
			t.Fatal("native IsAlive acceptance mismatch")
		}
		if c.Accepted && (nonce != c.Nonce || !bytes.Equal(EncodeIsAlive(nonce), raw)) {
			t.Fatal("native IsAlive nonce or encoding mismatch")
		}
	}
	factory := 0
	for _, c := range fixture.Factory {
		if c.PacketType != 18 {
			continue
		}
		factory++
		raw, err := hex.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := DecodeIsAlive(raw)
		if err != nil || nonce != c.Nonce {
			t.Fatal("native factory IsAlive mismatch")
		}
	}
	if cases < 2 || factory < 1 {
		t.Fatal("missing native IsAlive cases")
	}
}

func TestIsAliveReplyMatchesOriginalSerializer(t *testing.T) {
	data, err := os.ReadFile("testdata/native-responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Reply struct {
			Nonce   uint64 `json:"nonce"`
			Encoded string `json:"encoded_hex"`
		} `json:"is_alive_reply"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Reply.Encoded == "" {
		t.Fatal("missing original IsAlive serializer evidence")
	}
	raw, err := hex.DecodeString(fixture.Reply.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(EncodeIsAliveReply(fixture.Reply.Nonce), raw) {
		t.Fatal("original IsAlive serializer mismatch")
	}
	got, err := DecodeIsAliveReply(raw)
	if err != nil || got != fixture.Reply.Nonce {
		t.Fatal("original IsAlive reply decode mismatch")
	}
}
