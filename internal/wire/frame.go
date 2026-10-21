// Package wire implements only the observed ROS TCP frame boundaries.
// It does not implement authentication, encryption, network management or VPN transport.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DefaultLimit is a resource bound, not a recovered Radmin protocol maximum.
const DefaultLimit uint32 = 1 << 20

var ErrFrameTooLarge = errors.New("frame exceeds configured limit")
var ErrInvalidLimit = errors.New("frame limit must be positive")

// ReadFrame reads a four-byte big-endian body length followed by exactly that body.
// EOF before a header differs from truncated headers/bodies (io.ErrUnexpectedEOF).
func ReadFrame(r io.Reader, limit uint32) ([]byte, error) {
	if limit == 0 {
		return nil, ErrInvalidLimit
	}
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > limit {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, size, limit)
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

func WriteFrame(w io.Writer, body []byte, limit uint32) error {
	if limit == 0 {
		return ErrInvalidLimit
	}
	if uint64(len(body)) > uint64(limit) {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	for _, part := range [][]byte{header[:], body} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
