package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const FrameMagic = 0x48445241 // "HDRA"

// Frame wraps an encrypted envelope with magic number, length, and HMAC
type Frame struct {
	Magic   uint32
	Length  uint32
	HMAC    [32]byte
	Payload []byte
}

func WriteFrame(w io.Writer, payload []byte, key *[32]byte) error {
	mac := hmac.New(sha256.New, key[:])
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	mac.Write(lenBuf)
	mac.Write(payload)

	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], FrameMagic)
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	copy(frame[8:], payload)
	hmacSum := mac.Sum(nil)
	frame = append(frame, hmacSum...)

	_, err := w.Write(frame)
	return err
}

func ReadFrame(r io.Reader, key *[32]byte) ([]byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != FrameMagic {
		return nil, errors.New("invalid frame magic")
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if length > 10*1024*1024 {
		return nil, errors.New("frame too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	hmacSum := make([]byte, 32)
	if _, err := io.ReadFull(r, hmacSum); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key[:])
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, length)
	mac.Write(lenBuf)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), hmacSum) {
		return nil, errors.New("HMAC verification failed")
	}
	return payload, nil
}
