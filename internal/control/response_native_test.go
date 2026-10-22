package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestErrorAgainstOriginalPacketFactory(t *testing.T) {
	data, err := os.ReadFile("testdata/native-responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Synthetic bool `json:"synthetic_only"`
		Factory   []struct {
			Input    string `json:"input_hex"`
			Accepted bool   `json:"accepted"`
			Type     uint32 `json:"packet_type"`
			Code     uint32 `json:"code"`
		} `json:"factory"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Synthetic {
		t.Fatal("expected synthetic original-code evidence")
	}
	count := 0
	for _, c := range fixture.Factory {
		if c.Type != PacketError {
			continue
		}
		if !c.Accepted {
			t.Fatal("original factory rejected error fixture")
		}
		raw, err := hex.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeError(c.Code)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("error response differs from original factory fixture")
		}
		packet, err := DecodePacket(raw)
		if err != nil || packet.Type != PacketError {
			t.Fatal("error response dispatch mismatch")
		}
		count++
	}
	if count != 2 {
		t.Fatal("missing original factory error fixtures")
	}
}
