package control

import "encoding/binary"

const (
	isAlivePacketTypeTag uint32 = 0x01000320
	isAliveHeaderTag     uint32 = 0x123c
	isAliveOpcodeTag     uint32 = 0x010001d4
	isAliveContainerTag  uint32 = 0x1267
	isAliveNonceTag      uint32 = 0x02000232
)

// EncodeIsAlive builds the observed server probe: packet type 18 and a 64-bit
// nonce. The caller chooses the nonce; no meaning is assigned to its bits.
// Source: pinned RvROLClient packet factory type 18 and decoder 0x1008c6c0.
func EncodeIsAlive(nonce uint64) []byte {
	return append(isAliveField(isAlivePacketTypeTag, binary.BigEndian.AppendUint32(nil, 18)), isAliveNonce(nonce)...)
}

// DecodeIsAlive requires one packet type 18 and one nonce container. Unrelated
// fields remain opaque. Duplicate required fields are rejected by this decoder.
func DecodeIsAlive(data []byte) (uint64, error) {
	fields, err := Decode(data)
	if err != nil {
		return 0, err
	}
	typeValue, err := isAliveUnique(fields, isAlivePacketTypeTag)
	if err != nil || len(typeValue) != 4 || binary.BigEndian.Uint32(typeValue) != 18 {
		return 0, ErrMessage
	}
	return isAliveReadNonce(fields)
}

// EncodeIsAliveReply reproduces the client serializer's opcode 27 response.
// Its opcode is inside 0x123c, distinct from the ordinary request command field.
// Source: pinned RvROLClient client serializer 0x10088e90.
func EncodeIsAliveReply(nonce uint64) []byte {
	header := isAliveField(isAliveOpcodeTag, binary.BigEndian.AppendUint32(nil, 27))
	return isAliveField(isAliveHeaderTag, append(header, isAliveNonce(nonce)...))
}

func DecodeIsAliveReply(data []byte) (uint64, error) {
	fields, err := Decode(data)
	if err != nil {
		return 0, err
	}
	header, err := isAliveUnique(fields, isAliveHeaderTag)
	if err != nil {
		return 0, err
	}
	headerFields, err := Decode(header)
	if err != nil {
		return 0, err
	}
	opcode, err := isAliveUnique(headerFields, isAliveOpcodeTag)
	if err != nil || len(opcode) != 4 || binary.BigEndian.Uint32(opcode) != 27 {
		return 0, ErrMessage
	}
	return isAliveReadNonce(headerFields)
}

func isAliveReadNonce(fields []Field) (uint64, error) {
	container, err := isAliveUnique(fields, isAliveContainerTag)
	if err != nil {
		return 0, err
	}
	children, err := Decode(container)
	if err != nil {
		return 0, err
	}
	nonce, err := isAliveUnique(children, isAliveNonceTag)
	if err != nil || len(nonce) != 8 {
		return 0, ErrMessage
	}
	return binary.BigEndian.Uint64(nonce), nil
}

func isAliveUnique(fields []Field, tag uint32) ([]byte, error) {
	var result []byte
	for _, field := range fields {
		if field.Tag == tag {
			if result != nil {
				return nil, ErrMessage
			}
			result = field.Value
		}
	}
	if result == nil {
		return nil, ErrMessage
	}
	return result, nil
}

// These fixed, small records cannot exceed the general encoder's limits.
func isAliveField(tag uint32, value []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
	out = binary.BigEndian.AppendUint32(out, tag)
	return append(out, value...)
}

func isAliveNonce(nonce uint64) []byte {
	return isAliveField(isAliveContainerTag, isAliveField(isAliveNonceTag, binary.BigEndian.AppendUint64(nil, nonce)))
}
