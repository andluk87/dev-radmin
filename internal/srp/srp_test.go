package srp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func hello(id uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], id)
	return append(stateField(1), field(0x20000000, b[:])...)
}
func testRecord(t *testing.T) Record {
	t.Helper()
	r, err := Derive(42, []byte("research-only-password"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestIdentityByteOrder(t *testing.T) {
	if got := hex.EncodeToString(IdentityBytes(0x1122334455667788)); got != "7788556633441122" {
		t.Fatal(got)
	}
}

func TestVerifierMatchesOriginalHelper(t *testing.T) {
	b, err := os.ReadFile("testdata/native-verifiers.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		SyntheticOnly bool `json:"synthetic_only"`
		Vectors       []struct {
			ID       uint64 `json:"user_id"`
			Salt     string `json:"salt_hex"`
			Verifier string `json:"verifier_hex"`
			Password string `json:"password_hex"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	if !data.SyntheticOnly || len(data.Vectors) != 3 {
		t.Fatal("missing synthetic native vectors")
	}
	for _, v := range data.Vectors {
		salt, err := hex.DecodeString(v.Salt)
		if err != nil {
			t.Fatal(err)
		}
		password, err := hex.DecodeString(v.Password)
		if err != nil {
			t.Fatal(err)
		}
		record, err := Derive(v.ID, password, salt)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(record.Verifier) != v.Verifier {
			t.Fatalf("native verifier mismatch for fixture %d", v.ID)
		}
	}
}

func TestNoKeyBeforeValidProof(t *testing.T) {
	s, err := NewServer(testRecord(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SessionKey(); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
	if _, done, err := s.Step(hello(42)); err != nil || done {
		t.Fatalf("hello: %v %v", done, err)
	}
	if _, done, err := s.Step(append(stateField(3), field(0x60000000, []byte{5})...)); err != nil || done {
		t.Fatalf("public: %v %v", done, err)
	}
	if _, err = s.SessionKey(); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
	if _, _, err = s.Step(append(stateField(5), field(0x70000000, make([]byte, 20))...)); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if _, err = s.SessionKey(); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
	if _, _, err = s.Step(hello(42)); !errors.Is(err, ErrProtocol) {
		t.Fatal("failed context was reusable")
	}
}

func TestRejectInvalidPublicValues(t *testing.T) {
	for _, value := range [][]byte{{0}, modulus().Bytes()} {
		s, _ := NewServer(testRecord(t), nil)
		if _, _, err := s.Step(hello(42)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Step(append(stateField(3), field(0x60000000, value)...)); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
		if _, err := s.SessionKey(); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatal(err)
		}
	}
}

func TestRejectMalformedOrOutOfOrderMessages(t *testing.T) {
	inputs := [][]byte{{1, 2}, append(hello(42), field(0x20000000, make([]byte, 8))...), stateField(3), hello(43), make([]byte, 4097)}
	for _, input := range inputs {
		s, _ := NewServer(testRecord(t), nil)
		if _, _, err := s.Step(input); err == nil {
			t.Fatal("invalid input accepted")
		}
		if _, _, err := s.Step(hello(42)); !errors.Is(err, ErrProtocol) {
			t.Fatal("invalid context was reusable")
		}
	}
}

func TestEntropyFailureDoesNotYieldKey(t *testing.T) {
	s, _ := NewServer(testRecord(t), bytes.NewReader(nil))
	if _, _, err := s.Step(hello(42)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Step(append(stateField(3), field(0x60000000, []byte{5})...)); err == nil {
		t.Fatal("missing randomness accepted")
	}
	if _, err := s.SessionKey(); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
}
