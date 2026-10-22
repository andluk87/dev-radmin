package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestNativeNetworkTypedRequests(t *testing.T) {
	data, err := os.ReadFile("testdata/native-network-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Synthetic bool `json:"synthetic_only"`
		Cases     []struct {
			Name    string `json:"case"`
			Command uint32 `json:"command"`
			Raw     string `json:"request_hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Synthetic || len(fixture.Cases) != 6 {
		t.Fatal("missing native network fixtures")
	}
	for _, c := range fixture.Cases {
		raw, err := hex.DecodeString(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		var encoded []byte
		switch c.Command {
		case JoinCommand:
			join, e := DecodeJoinRequest(raw)
			if e != nil {
				t.Fatal(e)
			}
			encoded, err = EncodeJoinRequest(join)
		case ManageCommand:
			manage, e := DecodeManageRequest(raw)
			if e != nil {
				t.Fatal(e)
			}
			encoded, err = EncodeManageRequest(manage)
		default:
			t.Fatal("unexpected native command")
		}
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatalf("native typed request mismatch for %s: %v", c.Name, err)
		}
	}
}

func TestNetworkNameValidation(t *testing.T) {
	for _, name := range []string{"Тестовая сеть", "research 🐈", "a\x01b"} {
		raw, err := EncodeJoinRequest(JoinRequest{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		join, err := DecodeJoinRequest(raw)
		if err != nil || join.Name != name {
			t.Fatalf("unicode name mismatch: %v", err)
		}
	}
	for _, name := range []string{"x\x00y", string([]byte{0xff})} {
		if _, err := EncodeJoinRequest(JoinRequest{Name: name}); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
	for _, value := range [][]byte{
		{0, 1},          // Empty name.
		{0, 97, 0, 0},   // Wrong native terminator.
		{0, 97, 0},      // Odd length.
		{0xd8, 0, 0, 1}, // Unpaired high surrogate.
		{0xdc, 0, 0, 1}, // Unpaired low surrogate.
		{0, 0, 0, 1},    // Embedded NUL.
	} {
		if _, err := decodeNetworkName(value); err == nil {
			t.Fatalf("invalid name bytes %x accepted", value)
		}
	}
}

func TestNetworkStrictFields(t *testing.T) {
	name, _ := encodeNetworkName("test")
	good := []Field{{Tag: NetworkNameTag, Value: name}, wordField(NetworkFlagTag, 0)}
	encode := func(fields []Field) []byte {
		t.Helper()
		body, err := Encode(fields)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeRequest(Request{Command: JoinCommand, Fields: []Field{{Tag: JoinTag, Value: body}}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, fields := range [][]Field{
		{{Tag: NetworkNameTag, Value: name}},
		{wordField(NetworkFlagTag, 0)},
		{{Tag: NetworkProofTag, Value: []byte{1}}, wordField(NetworkFlagTag, 0)},
		append(append([]Field{}, good...), wordField(NetworkFlagTag, 0)),
		{{Tag: NetworkNameTag, Value: name}, wordField(NetworkFlagTag, 2)},
		append(append([]Field{}, good...), Field{Tag: JoinParameter3Tag, Value: []byte{1}}),
		append(append([]Field{}, good...), Field{Tag: JoinParameter4Tag, Value: []byte{1}}),
	} {
		if _, err := DecodeJoinRequest(encode(fields)); err == nil {
			t.Fatal("invalid join fields accepted")
		}
	}
	if _, err := EncodeJoinRequest(JoinRequest{}); err == nil {
		t.Fatal("empty join accepted")
	}
	if _, err := EncodeJoinRequest(JoinRequest{Proof: []byte{1}, Flag: true}); err == nil {
		t.Fatal("flag without name accepted")
	}
	if _, err := EncodeJoinRequest(JoinRequest{Name: "test", Fields: []Field{wordField(NetworkFlagTag, 1)}}); err == nil {
		t.Fatal("reserved join field accepted")
	}
	raw := encode(good)
	if _, err := DecodeManageRequest(raw); err == nil {
		t.Fatal("join interpreted as management")
	}
}

func TestNetworkOpaqueFields(t *testing.T) {
	join := JoinRequest{Name: "test", Proof: []byte("synthetic"), Fields: []Field{{Tag: 99, Value: []byte{1}}}, RequestFields: []Field{{Tag: 98, Value: []byte{2}}}}
	raw, err := EncodeJoinRequest(join)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeJoinRequest(raw)
	if err != nil || len(got.Fields) != 1 || len(got.RequestFields) != 1 || !bytes.Equal(got.Proof, join.Proof) {
		t.Fatalf("join opaque fields: %v", err)
	}
	// Input mutation must not modify preserved proof or operation bytes.
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(got.Proof, join.Proof) {
		t.Fatal("proof aliased input")
	}
	manage := ManageRequest{Operation: []byte("opaque operation, not parsed"), Fields: []Field{{Tag: 98, Value: []byte{2}}}}
	raw, err = EncodeManageRequest(manage)
	if err != nil {
		t.Fatal(err)
	}
	gotManage, err := DecodeManageRequest(raw)
	if err != nil || !bytes.Equal(gotManage.Operation, manage.Operation) || len(gotManage.Fields) != 1 {
		t.Fatalf("management opaque fields: %v", err)
	}
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(gotManage.Operation, manage.Operation) {
		t.Fatal("operation aliased input")
	}
	if _, err := EncodeManageRequest(ManageRequest{}); err == nil {
		t.Fatal("empty operation accepted")
	}
	if _, err := EncodeManageRequest(ManageRequest{Operation: []byte{1}, Fields: []Field{{Tag: ManageTag, Value: []byte{2}}}}); err == nil {
		t.Fatal("duplicate operation accepted")
	}
	bad, _ := EncodeRequest(Request{Command: ManageCommand, Fields: []Field{{Tag: ManageTag, Value: []byte{1}}, {Tag: ManageTag, Value: []byte{2}}}})
	if _, err := DecodeManageRequest(bad); err == nil {
		t.Fatal("duplicate operation decoded")
	}
	missing, _ := EncodeRequest(Request{Command: ManageCommand})
	if _, err := DecodeManageRequest(missing); err == nil {
		t.Fatal("missing operation decoded")
	}
}
