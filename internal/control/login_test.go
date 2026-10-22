package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestNativeModernLogin(t *testing.T) {
	data, err := os.ReadFile("testdata/native-login.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Kind, Input string
			Accepted    bool
			Type        uint32 `json:"packet_type"`
			Raw         string `json:"input_hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range fixture.Cases {
		if c.Kind != "modern_login" {
			continue
		}
		found = true
		raw, err := hex.DecodeString(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		login, err := DecodeLoginComplete(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !c.Accepted || c.Type != 21 || login.Version != 75 || login.Value25B != 1 {
			t.Fatal("native login mismatch")
		}
		encoded, err := EncodeLoginComplete(login)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("native bytes mismatch")
		}
	}
	if !found {
		t.Fatal("missing native fixture")
	}
}
func TestLoginValidation(t *testing.T) {
	valid := LoginComplete{Version: 75, Value25B: 1, EndpointsA: []string{"127.0.0.1"}, EndpointsB: []string{"127.0.0.1"}}
	for _, bad := range []string{"", "a\x00b", string([]byte{255})} {
		login := valid
		login.EndpointsA = []string{bad}
		if _, err := EncodeLoginComplete(login); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	raw, err := EncodeLoginComplete(valid)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(raw); i++ {
		if _, err := DecodeLoginComplete(raw[:i]); err == nil {
			t.Fatal("truncation accepted")
		}
	}
	packet, _ := DecodePacket(raw)
	packet.Fields = append(packet.Fields, packet.Fields[0])
	dup, _ := EncodePacket(packet)
	if _, err := DecodeLoginComplete(dup); err == nil {
		t.Fatal("duplicate version")
	}
}
