package control

import "encoding/binary"

const (
	PacketTypeTag       uint32 = 0x01000320
	ErrorDetailsTag     uint32 = 0x123b
	ErrorCodeTag        uint32 = 0x010001d2
	PacketError         uint32 = 16
	PacketHeartbeat     uint32 = 17
	PacketIsAlive       uint32 = 18
	PacketLoginComplete uint32 = 21
)

// Packet is the flat TLV response body selected by the native packet factory.
// Fields with unimplemented semantics remain opaque.
type Packet struct {
	Type   uint32
	Fields []Field
}

func DecodePacket(data []byte) (Packet, error) {
	fields, err := Decode(data)
	if err != nil {
		return Packet{}, err
	}
	var result Packet
	found := false
	for _, f := range fields {
		if f.Tag == PacketTypeTag {
			if found || len(f.Value) != 4 {
				return Packet{}, ErrMessage
			}
			result.Type = binary.BigEndian.Uint32(f.Value)
			found = true
		} else {
			result.Fields = append(result.Fields, f)
		}
	}
	if !found {
		return Packet{}, ErrMessage
	}
	return result, nil
}

func EncodePacket(packet Packet) ([]byte, error) {
	if len(packet.Fields) >= MaxFields {
		return nil, ErrMessage
	}
	fields := make([]Field, 1, len(packet.Fields)+1)
	fields[0] = Field{Tag: PacketTypeTag, Value: binary.BigEndian.AppendUint32(nil, packet.Type)}
	for _, f := range packet.Fields {
		if f.Tag == PacketTypeTag {
			return nil, ErrMessage
		}
		fields = append(fields, f)
	}
	return Encode(fields)
}

// EncodeError creates a native-decodable generic error response. Code meanings
// are not assumed; a caller must supply the code used by its specific experiment.
func EncodeError(code uint32) ([]byte, error) {
	details, err := Encode([]Field{{Tag: ErrorCodeTag, Value: binary.BigEndian.AppendUint32(nil, code)}})
	if err != nil {
		return nil, err
	}
	return EncodePacket(Packet{Type: PacketError, Fields: []Field{{Tag: ErrorDetailsTag, Value: details}}})
}
