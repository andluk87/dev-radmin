package control

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

const (
	LoginVersionTag    uint32 = 0x010001f1
	LoginValueTag      uint32 = 0x0100025b
	LoginEndpointsATag uint32 = 0x1343
	LoginEndpointATag  uint32 = 0x0e000370
	LoginEndpointsBTag uint32 = 0x1340
	LoginEndpointBTag  uint32 = 0x0e00036c
)

// LoginComplete contains fields accepted by the pinned original packet factory.
// Value25B and the endpoint lists retain neutral names until their full meanings
// are established. Decodability alone does not establish a working VPN login.
type LoginComplete struct {
	Version                uint32
	Value25B               uint32
	EndpointsA, EndpointsB []string
}

func loginEndpoints(tag uint32, values []string) ([]byte, error) {
	if len(values) == 0 || len(values) > MaxFields {
		return nil, ErrMessage
	}
	fields := make([]Field, 0, len(values))
	for _, value := range values {
		if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || len(value) > 4096 {
			return nil, ErrMessage
		}
		fields = append(fields, Field{Tag: tag, Value: append([]byte(value), 0)})
	}
	return Encode(fields)
}

func EncodeLoginComplete(login LoginComplete) ([]byte, error) {
	if login.Version != 75 {
		return nil, ErrMessage
	}
	a, err := loginEndpoints(LoginEndpointATag, login.EndpointsA)
	if err != nil {
		return nil, err
	}
	b, err := loginEndpoints(LoginEndpointBTag, login.EndpointsB)
	if err != nil {
		return nil, err
	}
	return EncodePacket(Packet{Type: PacketLoginComplete, Fields: []Field{
		wordField(LoginVersionTag, login.Version), wordField(LoginValueTag, login.Value25B),
		{Tag: LoginEndpointsATag, Value: a}, {Tag: LoginEndpointsBTag, Value: b},
	}})
}

func DecodeLoginComplete(data []byte) (LoginComplete, error) {
	packet, err := DecodePacket(data)
	if err != nil || packet.Type != PacketLoginComplete {
		return LoginComplete{}, ErrMessage
	}
	version, err := isAliveUnique(packet.Fields, LoginVersionTag)
	if err != nil || len(version) != 4 {
		return LoginComplete{}, ErrMessage
	}
	value, err := isAliveUnique(packet.Fields, LoginValueTag)
	if err != nil || len(value) != 4 {
		return LoginComplete{}, ErrMessage
	}
	result := LoginComplete{Version: binary.BigEndian.Uint32(version), Value25B: binary.BigEndian.Uint32(value)}
	if result.Version != 75 {
		return LoginComplete{}, ErrMessage
	}
	for _, target := range []struct {
		container, tag uint32
		out            *[]string
	}{
		{LoginEndpointsATag, LoginEndpointATag, &result.EndpointsA},
		{LoginEndpointsBTag, LoginEndpointBTag, &result.EndpointsB},
	} {
		body, err := isAliveUnique(packet.Fields, target.container)
		if err != nil {
			return LoginComplete{}, err
		}
		fields, err := Decode(body)
		if err != nil {
			return LoginComplete{}, err
		}
		for _, field := range fields {
			if field.Tag != target.tag {
				continue
			}
			v := field.Value
			if len(v) < 2 || v[len(v)-1] != 0 || !utf8.Valid(v[:len(v)-1]) || strings.ContainsRune(string(v[:len(v)-1]), 0) {
				return LoginComplete{}, ErrMessage
			}
			*target.out = append(*target.out, string(v[:len(v)-1]))
		}
		if len(*target.out) == 0 {
			return LoginComplete{}, ErrMessage
		}
	}
	return result, nil
}
