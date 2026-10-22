package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestOriginalRequestSerializer(t *testing.T) {
	data, err := os.ReadFile("testdata/native-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SyntheticOnly bool   `json:"synthetic_only"`
		DLLHash       string `json:"dll_sha256"`
		Cases         []struct {
			Mode       int    `json:"mode"`
			Request    string `json:"request_hex"`
			ContextTag string `json:"context_tag"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.SyntheticOnly || fixture.DLLHash != "6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177" || len(fixture.Cases) != 3 {
		t.Fatal("missing native request evidence")
	}
	for _, c := range fixture.Cases {
		t.Run(fmt.Sprintf("mode%d", c.Mode), func(t *testing.T) {
			raw, err := hex.DecodeString(c.Request)
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			if request.Command != 20 {
				t.Fatalf("native command = %d", request.Command)
			}
			if c.ContextTag != "0x1232" {
				t.Fatal("unexpected logical context")
			}
			encoded, err := EncodeRequest(request)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatalf("native request byte mismatch: %v", err)
			}
			// The original serializer emits fields directly. 0x1232 belongs to the
			// builder context and must not be inserted into the transmitted bytes.
			first, _, err := ReadField(raw)
			if err != nil || first.Tag != CommandTag {
				t.Fatal("native request is not flat")
			}
		})
	}
}

func TestOriginalNetworkRequestSerializer(t *testing.T) {
	data, err := os.ReadFile("testdata/native-network-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SyntheticOnly bool `json:"synthetic_only"`
		Cases         []struct {
			Name    string `json:"case"`
			Command uint32 `json:"command"`
			Request string `json:"request_hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.SyntheticOnly || len(fixture.Cases) != 6 {
		t.Fatal("missing native network request evidence")
	}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%s%d", c.Name, i), func(t *testing.T) {
			raw, err := hex.DecodeString(c.Request)
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeRequest(raw)
			if err != nil || request.Command != c.Command {
				t.Fatalf("native request decode: %v", err)
			}
			encoded, err := EncodeRequest(request)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatalf("native network request byte mismatch: %v", err)
			}
		})
	}
}
