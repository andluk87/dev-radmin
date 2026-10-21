// Package channel reproduces the pinned helper's legacy CChannel for research.
// AES-CBC and the unkeyed MD4-derived checksum are compatibility features, not AEAD.
// Instances carry ordered state in each direction and are not safe for concurrent use.
package channel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const MaxPayload = 1 << 20

var ErrRecord = errors.New("invalid legacy channel record or failed channel")

type Channel struct {
	enc, dec     cipher.BlockMode
	encIV, decIV [16]byte
	failed       bool
}

// Rekey preserves both CBC chains, as the helper's SetKeyEnc/SetKeyDec do.
// It is only valid after successful SRP proof verification by the caller.
func (c *Channel) Rekey(encKey, decKey []byte) error {
	if c.failed || len(encKey) != 32 || len(decKey) != 32 {
		return ErrRecord
	}
	enc, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	dec, err := aes.NewCipher(decKey)
	if err != nil {
		return err
	}
	c.enc = cipher.NewCBCEncrypter(enc, c.encIV[:])
	c.dec = cipher.NewCBCDecrypter(dec, c.decIV[:])
	return nil
}

// New requires independent 32-byte directional keys. Both IVs start at zero.
func New(encKey, decKey []byte) (*Channel, error) {
	if len(encKey) != 32 || len(decKey) != 32 {
		return nil, ErrRecord
	}
	enc, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	dec, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	return &Channel{enc: cipher.NewCBCEncrypter(enc, make([]byte, 16)), dec: cipher.NewCBCDecrypter(dec, make([]byte, 16))}, nil
}

func (c *Channel) Encrypt(payload []byte) ([]byte, error) {
	if c.failed || len(payload) == 0 || len(payload) > MaxPayload {
		return nil, ErrRecord
	}
	size := ((len(payload)+8)/16 + 1) * 16
	out := make([]byte, size)
	copy(out, payload)
	for i := len(payload); i < size-9; i++ {
		out[i] = 0xcc
	}
	check := checksum(out[:size-9])
	copy(out[size-9:], check[:])
	out[size-1] = byte(size - len(payload))
	c.enc.CryptBlocks(out, out)
	copy(c.encIV[:], out[len(out)-16:])
	return out, nil
}

// Decrypt verifies the legacy checksum before returning any plaintext. Any rejected
// record permanently invalidates the instance: CBC state cannot be resynchronized.
func (c *Channel) Decrypt(record []byte) ([]byte, error) {
	reject := func() ([]byte, error) { c.failed = true; return nil, ErrRecord }
	if c.failed || len(record) == 0 || len(record)%16 != 0 || len(record) > MaxPayload+24 {
		return reject()
	}
	plain := append([]byte(nil), record...)
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	c.dec.CryptBlocks(plain, plain)
	copy(c.decIV[:], record[len(record)-16:])
	padding := int(plain[len(plain)-1])
	if padding < 9 || padding >= 25 || padding >= len(plain) {
		return reject()
	}
	length := len(plain) - padding
	if length > MaxPayload {
		return reject()
	}
	check := checksum(plain[:len(plain)-9])
	if subtle.ConstantTimeCompare(check[:], plain[len(plain)-9:len(plain)-1]) != 1 {
		return reject()
	}
	// The native decoder does not require fill bytes to be 0xcc. The checksum
	// covers them, and accepting that behavior preserves observed compatibility.
	return append([]byte(nil), plain[:length]...), nil
}

func checksum(data []byte) [8]byte {
	var sum uint64
	for len(data) >= 8 {
		sum += binary.LittleEndian.Uint64(data)
		data = data[8:]
	}
	for i, b := range data {
		sum += uint64(b) << (8 * i)
	}
	digest := md4Uint64(sum)
	var out [8]byte
	for i := range out {
		out[i] = digest[i] + digest[i+8]
	}
	return out
}

// md4Uint64 computes MD4 of exactly eight little-endian bytes. Keeping this
// fixed-size avoids exposing a general-purpose obsolete hash API.
func md4Uint64(input uint64) [16]byte {
	var x [16]uint32
	x[0], x[1], x[2], x[14] = uint32(input), uint32(input>>32), 0x80, 64
	initial := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	v := initial
	for round := 0; round < 3; round++ {
		for i := 0; i < 16; i++ {
			idx := (4 - i%4) % 4
			a, b, c, d := v[idx], v[(idx+1)%4], v[(idx+2)%4], v[(idx+3)%4]
			k, shift, f, constant := i, 0, uint32(0), uint32(0)
			switch round {
			case 0:
				shift = []int{3, 7, 11, 19}[i%4]
				f = (b & c) | (^b & d)
			case 1:
				k = (i%4)*4 + i/4
				shift = []int{3, 5, 9, 13}[i%4]
				f = (b & c) | (b & d) | (c & d)
				constant = 0x5a827999
			case 2:
				k = []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}[i]
				shift = []int{3, 9, 11, 15}[i%4]
				f = b ^ c ^ d
				constant = 0x6ed9eba1
			}
			v[idx] = bits.RotateLeft32(a+f+x[k]+constant, shift)
		}
	}
	var out [16]byte
	for i := range v {
		binary.LittleEndian.PutUint32(out[i*4:], v[i]+initial[i])
	}
	return out
}
