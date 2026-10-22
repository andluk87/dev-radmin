package control

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	JoinCommand       uint32 = 39
	ManageCommand     uint32 = 52
	JoinTag           uint32 = 0x131c
	ManageTag         uint32 = 0x1319
	NetworkNameTag    uint32 = 0x03000306
	NetworkFlagTag    uint32 = 0x0b00033f
	NetworkProofTag   uint32 = 0x0a00030e
	JoinParameter3Tag uint32 = 0x02000340
	JoinParameter4Tag uint32 = 0x0100034a
	JoinParameter5Tag uint32 = 0x010003be
)

// JoinRequest represents observed join fields. Proof is supplied opaque: this
// package never manufactures or validates a network authentication proof.
// Parameter names remain neutral until their meanings are confirmed.
type JoinRequest struct {
	Name          string
	Flag          bool
	Proof         []byte
	Parameter3    uint64
	Parameter4    uint32
	Parameter5    uint32
	Fields        []Field // Unknown nested join fields.
	RequestFields []Field // Unknown outer request fields.
}

// ManageRequest preserves the operation supplied to the original management
// wrapper. Operation semantics and authorization are not implemented here.
type ManageRequest struct {
	Operation []byte
	Fields    []Field
}

func joinKnown(tag uint32) bool {
	switch tag {
	case NetworkNameTag, NetworkFlagTag, NetworkProofTag, JoinParameter3Tag, JoinParameter4Tag, JoinParameter5Tag:
		return true
	}
	return false
}

func wordField(tag, value uint32) Field {
	return Field{Tag: tag, Value: binary.BigEndian.AppendUint32(nil, value)}
}

// encodeNetworkName reproduces the native type-3 writer: UTF16BE code units
// followed by 0001. The native source string is NUL-terminated.
func encodeNetworkName(name string) ([]byte, error) {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || len(name) > MaxMessage {
		return nil, ErrMessage
	}
	units := utf16.Encode([]rune(name))
	if len(units) > (MaxMessage-2)/2 {
		return nil, ErrMessage
	}
	result := make([]byte, 0, 2*len(units)+2)
	for _, unit := range units {
		result = binary.BigEndian.AppendUint16(result, unit)
	}
	return binary.BigEndian.AppendUint16(result, 1), nil
}

func decodeNetworkName(data []byte) (string, error) {
	if len(data) < 4 || len(data)%2 != 0 || binary.BigEndian.Uint16(data[len(data)-2:]) != 1 {
		return "", ErrMessage
	}
	units := make([]uint16, 0, len(data)/2-1)
	for i := 0; i < len(data)-2; i += 2 {
		unit := binary.BigEndian.Uint16(data[i:])
		if unit == 0 {
			return "", ErrMessage
		}
		units = append(units, unit)
	}
	for i := 0; i < len(units); i++ {
		unit := units[i]
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", ErrMessage
			}
			i++
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return "", ErrMessage
		}
	}
	return string(utf16.Decode(units)), nil
}

func EncodeJoinRequest(join JoinRequest) ([]byte, error) {
	if join.Name == "" && (len(join.Proof) == 0 || join.Flag) {
		return nil, ErrMessage
	}
	var nested []Field
	if join.Name != "" {
		name, err := encodeNetworkName(join.Name)
		if err != nil {
			return nil, err
		}
		nested = append(nested, Field{Tag: NetworkNameTag, Value: name})
		flag := uint32(0)
		if join.Flag {
			flag = 1
		}
		nested = append(nested, wordField(NetworkFlagTag, flag))
	}
	if len(join.Proof) > 0 {
		nested = append(nested, Field{Tag: NetworkProofTag, Value: join.Proof})
	}
	if join.Parameter3 != 0 {
		nested = append(nested, Field{Tag: JoinParameter3Tag, Value: binary.BigEndian.AppendUint64(nil, join.Parameter3)})
	}
	if join.Parameter4 != 0 {
		nested = append(nested, wordField(JoinParameter4Tag, join.Parameter4))
	}
	if join.Parameter5 != 0 {
		nested = append(nested, wordField(JoinParameter5Tag, join.Parameter5))
	}
	for _, field := range join.Fields {
		if joinKnown(field.Tag) {
			return nil, ErrMessage
		}
		nested = append(nested, field)
	}
	body, err := Encode(nested)
	if err != nil {
		return nil, err
	}
	fields := []Field{{Tag: JoinTag, Value: body}}
	for _, field := range join.RequestFields {
		if field.Tag == JoinTag {
			return nil, ErrMessage
		}
		fields = append(fields, field)
	}
	return EncodeRequest(Request{Command: JoinCommand, Fields: fields})
}

func DecodeJoinRequest(data []byte) (JoinRequest, error) {
	request, err := DecodeRequest(data)
	if err != nil || request.Command != JoinCommand {
		return JoinRequest{}, ErrMessage
	}
	var result JoinRequest
	var body []byte
	for _, field := range request.Fields {
		if field.Tag == JoinTag {
			if body != nil {
				return JoinRequest{}, ErrMessage
			}
			body = field.Value
		} else {
			result.RequestFields = append(result.RequestFields, field)
		}
	}
	nested, err := Decode(body)
	if err != nil {
		return JoinRequest{}, err
	}
	seen := make(map[uint32]bool)
	for _, field := range nested {
		if joinKnown(field.Tag) {
			if seen[field.Tag] {
				return JoinRequest{}, ErrMessage
			}
			seen[field.Tag] = true
		}
		switch field.Tag {
		case NetworkNameTag:
			result.Name, err = decodeNetworkName(field.Value)
			if err != nil {
				return JoinRequest{}, err
			}
		case NetworkFlagTag:
			if len(field.Value) != 4 {
				return JoinRequest{}, ErrMessage
			}
			flag := binary.BigEndian.Uint32(field.Value)
			if flag > 1 {
				return JoinRequest{}, ErrMessage
			}
			result.Flag = flag == 1
		case NetworkProofTag:
			result.Proof = field.Value
		case JoinParameter3Tag:
			if len(field.Value) != 8 {
				return JoinRequest{}, ErrMessage
			}
			result.Parameter3 = binary.BigEndian.Uint64(field.Value)
		case JoinParameter4Tag, JoinParameter5Tag:
			if len(field.Value) != 4 {
				return JoinRequest{}, ErrMessage
			}
			if field.Tag == JoinParameter4Tag {
				result.Parameter4 = binary.BigEndian.Uint32(field.Value)
			} else {
				result.Parameter5 = binary.BigEndian.Uint32(field.Value)
			}
		default:
			result.Fields = append(result.Fields, field)
		}
	}
	// Native name-based serialization always includes its flag. Proof-only
	// serialization emits neither a name nor a flag.
	if seen[NetworkNameTag] != seen[NetworkFlagTag] || (result.Name == "" && len(result.Proof) == 0) {
		return JoinRequest{}, ErrMessage
	}
	return result, nil
}

func EncodeManageRequest(manage ManageRequest) ([]byte, error) {
	if len(manage.Operation) == 0 {
		return nil, ErrMessage
	}
	fields := []Field{{Tag: ManageTag, Value: manage.Operation}}
	for _, field := range manage.Fields {
		if field.Tag == ManageTag {
			return nil, ErrMessage
		}
		fields = append(fields, field)
	}
	return EncodeRequest(Request{Command: ManageCommand, Fields: fields})
}

func DecodeManageRequest(data []byte) (ManageRequest, error) {
	request, err := DecodeRequest(data)
	if err != nil || request.Command != ManageCommand {
		return ManageRequest{}, ErrMessage
	}
	var result ManageRequest
	for _, field := range request.Fields {
		if field.Tag == ManageTag {
			if result.Operation != nil {
				return ManageRequest{}, ErrMessage
			}
			result.Operation = field.Value
		} else {
			result.Fields = append(result.Fields, field)
		}
	}
	if len(result.Operation) == 0 {
		return ManageRequest{}, ErrMessage
	}
	return result, nil
}
