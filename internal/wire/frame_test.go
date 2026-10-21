package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type fragmentedReader struct{ io.Reader }

func (r fragmentedReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }

func TestObservedVersionPrefix(t *testing.T) {
	packet := []byte{0, 0, 0, 4, 3, 0, 0, 0}
	body, err := ReadFrame(fragmentedReader{bytes.NewReader(packet)}, DefaultLimit)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(body) != 3 {
		t.Fatalf("unexpected version body: %x", body)
	}
	var out shortWriter
	if err = WriteFrame(&out, body, DefaultLimit); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), packet) {
		t.Fatalf("encoded %x", out.Bytes())
	}
}

func TestObservedFrameLengthsWithSyntheticBodies(t *testing.T) {
	lengths := []int{4, 192, 32, 224, 48, 288, 112, 4, 256, 224, 48, 1968, 96, 5072}
	var stream bytes.Buffer
	for _, size := range lengths {
		if err := WriteFrame(&stream, bytes.Repeat([]byte{0xa5}, size), DefaultLimit); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range lengths {
		b, err := ReadFrame(fragmentedReader{&stream}, DefaultLimit)
		if err != nil || len(b) != size {
			t.Fatalf("size %d: body=%d err=%v", size, len(b), err)
		}
	}
	if _, err := ReadFrame(&stream, DefaultLimit); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestTruncatedAndOversizedFrames(t *testing.T) {
	for _, input := range [][]byte{{0, 0}, {0, 0, 0, 4}, {0, 0, 0, 4, 1, 2}} {
		if _, err := ReadFrame(bytes.NewReader(input), DefaultLimit); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%x: %v", input, err)
		}
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0x7f, 0xff, 0xff, 0xff}), DefaultLimit); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil), 0); !errors.Is(err, ErrInvalidLimit) {
		t.Fatal(err)
	}
	if err := WriteFrame(io.Discard, make([]byte, 5), 4); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if err := WriteFrame(stalledWriter{}, []byte{3}, DefaultLimit); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
