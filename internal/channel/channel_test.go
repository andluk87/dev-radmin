package channel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type stream struct {
	Direction string `json:"direction"`
	Messages  []struct {
		Plain  string `json:"plaintext_hex"`
		Cipher string `json:"ciphertext_hex"`
	} `json:"messages"`
}
type fixture struct {
	Rejected      []string `json:"rejected_records_hex"`
	SyntheticOnly bool     `json:"synthetic_only"`
	ClientKey     string   `json:"client_key_hex"`
	ServerKey     string   `json:"server_key_hex"`
	Streams       []stream `json:"streams"`
	RekeyKey      string   `json:"rekey_key_hex"`
	RekeyStreams  []stream `json:"rekey_streams"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func load(t *testing.T) fixture {
	t.Helper()
	var f fixture
	b, e := os.ReadFile("testdata/native-channel.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	if !f.SyntheticOnly || len(f.Streams) != 2 {
		t.Fatal("missing native fixtures")
	}
	return f
}
func TestSequentialRecordsMatchNativeBothDirections(t *testing.T) {
	f := load(t)
	client, e := New(unhex(t, f.ClientKey), unhex(t, f.ServerKey))
	if e != nil {
		t.Fatal(e)
	}
	server, e := New(unhex(t, f.ServerKey), unhex(t, f.ClientKey))
	if e != nil {
		t.Fatal(e)
	}
	for phase, streams := range [][]stream{f.Streams, f.RekeyStreams} {
		expected := 13
		if phase == 1 {
			expected = 3
			if len(streams) != 2 {
				t.Fatal("missing native rekey vectors")
			}
			key := unhex(t, f.RekeyKey)
			if e := client.Rekey(key, key); e != nil {
				t.Fatal(e)
			}
			if e := server.Rekey(key, key); e != nil {
				t.Fatal(e)
			}
		}
		for _, stream := range streams {
			sender, receiver := client, server
			if stream.Direction == "server_to_client" {
				sender, receiver = server, client
			}
			if len(stream.Messages) != expected {
				t.Fatal("missing boundary cases")
			}
			for _, m := range stream.Messages {
				plain, want := unhex(t, m.Plain), unhex(t, m.Cipher)
				got, e := sender.Encrypt(plain)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatalf("native encryption mismatch len=%d err=%v", len(plain), e)
				}
				back, e := receiver.Decrypt(want)
				if e != nil || !bytes.Equal(back, plain) {
					t.Fatalf("native decryption mismatch len=%d err=%v", len(plain), e)
				}
			}
		}
	}
}

func TestMD4EightByteReferenceValues(t *testing.T) {
	// Independently checked with OpenSSL's legacy MD4 provider.
	for _, v := range []struct {
		input  uint64
		digest string
	}{
		{0x00cccccccccccc01, "ccf694cc6fa77c1b72478ae52880cc22"},
		{0x162a2724211e1b18, "dfec1cb3ac9dcd968f887baa3511524c"},
		{0x4c4844403c383430, "115341342137418bad0218b574086207"},
	} {
		got := md4Uint64(v.input)
		if hex.EncodeToString(got[:]) != v.digest {
			t.Fatal("MD4 reference mismatch")
		}
	}
}
func TestCorruptionAndOutOfOrderInvalidateChannel(t *testing.T) {
	f := load(t)
	first := unhex(t, f.Streams[0].Messages[0].Cipher)
	corrupted := append([]byte(nil), first...)
	corrupted[0] ^= 1
	inputs := [][]byte{nil, {1}, first[:15], corrupted, unhex(t, f.Streams[0].Messages[1].Cipher)}
	for _, encoded := range f.Rejected {
		inputs = append(inputs, unhex(t, encoded))
	}
	for _, input := range inputs {
		receiver, _ := New(unhex(t, f.ServerKey), unhex(t, f.ClientKey))
		if plain, e := receiver.Decrypt(input); e == nil || plain != nil {
			t.Fatal("invalid record released plaintext")
		}
		if plain, e := receiver.Decrypt(first); e == nil || plain != nil {
			t.Fatal("failed channel was reusable")
		}
		if e := receiver.Rekey(unhex(t, f.ServerKey), unhex(t, f.ClientKey)); e == nil {
			t.Fatal("failed channel accepted rekey")
		}
	}
}
func TestRecordBoundsAndKeyLengths(t *testing.T) {
	if _, e := New(make([]byte, 16), make([]byte, 32)); e == nil {
		t.Fatal("short AES key accepted")
	}
	key := make([]byte, 32)
	c, _ := New(key, key)
	if _, e := c.Encrypt(nil); e == nil {
		t.Fatal("empty payload accepted")
	}
	if _, e := c.Encrypt(make([]byte, MaxPayload+1)); e == nil {
		t.Fatal("oversized payload accepted")
	}
	m := bytes.Repeat([]byte{0x5a}, MaxPayload)
	enc, e := c.Encrypt(m)
	if e != nil {
		t.Fatal(e)
	}
	d, _ := New(key, key)
	back, e := d.Decrypt(enc)
	if e != nil || !bytes.Equal(m, back) {
		t.Fatal("maximum payload failed", e)
	}
}
