// Package srp implements the observed legacy helper SRP-6a exchange for research.
// SHA-1, the 1536-bit custom group, and MGF1 are compatibility requirements.
// math/big operations are not constant-time; this is not a production cryptographic service.
package srp

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

const modulusHex = "e634471e75f2d76a0a3f5e252c5a6efb48edad645d31d9ecbc400416e14f5c6c2ed378602d6eb8e9478b99e6474932393538b4be7177e0e05d3aaed17b5ae87aa20f3dad37af019518f45b6dde76b2bfdfb140f379cc15383b304b7975b907967553cd6fdaf08d68832b603120430a501067d21beb2ce2275a20036a2dc80f1c9d3ab9221afd5baceda5c2a31077c54fc6f274aaeba17ddd0b5c68f4f8e751a890a58648147a82e6f4f532ccdc939a12942799a713500e17dd4f6ff216cd54c7"
const groupBytes = 192

var ErrProtocol = errors.New("invalid helper SRP message or state")
var ErrAuthentication = errors.New("helper SRP authentication failed")
var ErrNotAuthenticated = errors.New("session has not authenticated")

type Record struct {
	UserID   uint64
	Salt     []byte
	Verifier []byte
}

func modulus() *big.Int { n, _ := new(big.Int).SetString(modulusHex, 16); return n }
func hash(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}
func padded(n *big.Int) []byte { return n.FillBytes(make([]byte, groupBytes)) }

// IdentityBytes is the helper's internal credential-name representation.
// It differs from the LE uint64 identifier in the helper TLV message.
func IdentityBytes(id uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, id)
	for i := 0; i < 8; i += 2 {
		b[i], b[i+1] = b[i+1], b[i]
	}
	return b
}

func Derive(id uint64, password, salt []byte) (Record, error) {
	if len(password) < 6 || len(salt) != 32 {
		return Record{}, ErrProtocol
	}
	x := new(big.Int).SetBytes(hash(salt, hash(IdentityBytes(id), []byte(":"), password)))
	v := new(big.Int).Exp(big.NewInt(5), x, modulus())
	return Record{id, append([]byte(nil), salt...), v.Bytes()}, nil
}

func mgf1(seed []byte) []byte {
	key := make([]byte, 0, 40)
	for i := uint32(0); i < 2; i++ {
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], i)
		key = append(key, hash(seed, counter[:])...)
	}
	return key
}

// Fields use a five-bit type and a 27-bit big-endian value length.
func field(tag uint32, value []byte) []byte {
	b := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(b, tag|uint32(len(value)))
	copy(b[4:], value)
	return b
}
func stateField(state uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], state)
	return field(0x10000000, b[:])
}
func parse(input []byte) (map[uint32][]byte, error) {
	if len(input) > 4096 {
		return nil, ErrProtocol
	}
	fields := make(map[uint32][]byte)
	for len(input) > 0 {
		if len(input) < 4 {
			return nil, ErrProtocol
		}
		header := binary.BigEndian.Uint32(input[:4])
		tag, size := header&0xf8000000, int(header&0x07ffffff)
		if size > len(input)-4 {
			return nil, ErrProtocol
		}
		if _, duplicate := fields[tag]; duplicate {
			return nil, ErrProtocol
		}
		fields[tag] = input[4 : 4+size]
		input = input[4+size:]
	}
	return fields, nil
}

type Server struct {
	record                          Record
	random                          io.Reader
	phase                           uint32
	failed                          bool
	key, expectedProof, serverProof []byte
}

func NewServer(record Record, random io.Reader) (*Server, error) {
	n := modulus()
	v := new(big.Int).SetBytes(record.Verifier)
	if len(record.Salt) != 32 || len(record.Verifier) > groupBytes || v.Sign() <= 0 || v.Cmp(n) >= 0 {
		return nil, ErrProtocol
	}
	if random == nil {
		random = rand.Reader
	}
	record.Salt = append([]byte(nil), record.Salt...)
	record.Verifier = append([]byte(nil), record.Verifier...)
	return &Server{record: record, random: random}, nil
}

func (s *Server) reject(err error) ([]byte, bool, error) {
	s.failed = true
	for _, b := range [][]byte{s.key, s.expectedProof, s.serverProof} {
		for i := range b {
			b[i] = 0
		}
	}
	s.key = nil
	s.expectedProof = nil
	s.serverProof = nil
	return nil, false, err
}

// Step operates on inner helper messages, not the complete Radmin VPN wire protocol.
func (s *Server) Step(input []byte) ([]byte, bool, error) {
	if s.failed || s.phase == 6 {
		return nil, false, ErrProtocol
	}
	fields, err := parse(input)
	if err != nil {
		return s.reject(err)
	}
	state, ok := fields[0x10000000]
	if !ok || len(state) != 4 || len(fields) != 2 {
		return s.reject(ErrProtocol)
	}
	value := binary.BigEndian.Uint32(state)
	switch s.phase {
	case 0:
		identity, ok := fields[0x20000000]
		if value != 1 || !ok || len(identity) != 8 {
			return s.reject(ErrProtocol)
		}
		if binary.LittleEndian.Uint64(identity) != s.record.UserID {
			return s.reject(ErrAuthentication)
		}
		out := stateField(2)
		out = append(out, field(0x30000000, padded(modulus()))...)
		out = append(out, field(0x40000000, []byte{5})...)
		out = append(out, field(0x50000000, s.record.Salt)...)
		s.phase = 2
		return out, false, nil
	case 2:
		aBytes, ok := fields[0x60000000]
		if value != 3 || !ok || len(aBytes) == 0 || len(aBytes) > groupBytes {
			return s.reject(ErrProtocol)
		}
		n := modulus()
		a := new(big.Int).SetBytes(aBytes)
		if a.Sign() <= 0 || a.Cmp(n) >= 0 {
			return s.reject(ErrAuthentication)
		}
		secretBytes := make([]byte, 32)
		if _, err := io.ReadFull(s.random, secretBytes); err != nil {
			return s.reject(err)
		}
		secret := new(big.Int).SetBytes(secretBytes)
		secret.Add(secret, big.NewInt(int64(n.BitLen())))
		for i := range secretBytes {
			secretBytes[i] = 0
		}
		g := big.NewInt(5)
		v := new(big.Int).SetBytes(s.record.Verifier)
		k := new(big.Int).SetBytes(hash(padded(n), padded(g)))
		b := new(big.Int).Exp(g, secret, n)
		b.Add(b, new(big.Int).Mul(k, v))
		b.Mod(b, n)
		if b.Sign() == 0 {
			return s.reject(ErrAuthentication)
		}
		bBytes := b.Bytes()
		u := new(big.Int).SetBytes(hash(padded(a), padded(b)))
		if u.Sign() == 0 {
			return s.reject(ErrAuthentication)
		}
		base := new(big.Int).Exp(v, u, n)
		base.Mul(base, a)
		base.Mod(base, n)
		shared := new(big.Int).Exp(base, secret, n)
		s.key = mgf1(shared.Bytes())
		left, right := hash(padded(n)), hash(g.Bytes())
		for i := range left {
			left[i] ^= right[i]
		}
		s.expectedProof = hash(left, hash(IdentityBytes(s.record.UserID)), s.record.Salt, aBytes, bBytes, s.key)
		s.serverProof = hash(aBytes, s.expectedProof, s.key)
		s.phase = 4
		return append(stateField(4), field(0x60000000, bBytes)...), false, nil
	case 4:
		proof, ok := fields[0x70000000]
		if value != 5 || !ok || len(proof) != sha1.Size {
			return s.reject(ErrProtocol)
		}
		if subtle.ConstantTimeCompare(proof, s.expectedProof) != 1 {
			return s.reject(ErrAuthentication)
		}
		s.phase = 6
		return append(stateField(6), field(0x70000000, s.serverProof)...), true, nil
	}
	return s.reject(ErrProtocol)
}

// SessionKey deliberately refuses access before proof verification, unlike the raw DLL getter.
func (s *Server) SessionKey() ([]byte, error) {
	if s.failed || s.phase != 6 {
		return nil, ErrNotAuthenticated
	}
	return append([]byte(nil), s.key...), nil
}
