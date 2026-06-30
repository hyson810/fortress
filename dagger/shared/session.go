package shared

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// TaskType enumerates commands the implant can execute
type TaskType uint8

const (
	TaskNone      TaskType = 0
	TaskShell     TaskType = 1
	TaskUpload    TaskType = 2
	TaskDownload  TaskType = 3
	TaskInject    TaskType = 4
	TaskLateral   TaskType = 5
	TaskPersist   TaskType = 6
	TaskSleep     TaskType = 7
	TaskExit      TaskType = 8
	TaskPlugin    TaskType = 9
	TaskKeyRotate TaskType = 10
)

// SessionEnvelope wraps every message between teamserver and implant
type SessionEnvelope struct {
	SessionID [16]byte
	Seq       uint64
	Type      uint8 // 0=task, 1=result, 2=register, 3=ack
	Payload   []byte
}

func (e *SessionEnvelope) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 16+8+1+4+len(e.Payload))
	copy(buf[0:16], e.SessionID[:])
	binary.BigEndian.PutUint64(buf[16:24], e.Seq)
	buf[24] = e.Type
	binary.BigEndian.PutUint32(buf[25:29], uint32(len(e.Payload)))
	copy(buf[29:], e.Payload)
	return buf, nil
}

var ErrUnderflow = errors.New("envelope underflow")

func UnmarshalEnvelope(r io.Reader) (*SessionEnvelope, error) {
	header := make([]byte, 29)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	e := &SessionEnvelope{}
	copy(e.SessionID[:], header[0:16])
	e.Seq = binary.BigEndian.Uint64(header[16:24])
	e.Type = header[24]
	payLen := binary.BigEndian.Uint32(header[25:29])
	if payLen > 10*1024*1024 {
		return nil, errors.New("payload too large")
	}
	e.Payload = make([]byte, payLen)
	if _, err := io.ReadFull(r, e.Payload); err != nil {
		return nil, err
	}
	return e, nil
}

// Task is the command sent to an implant
type Task struct {
	ID        [16]byte
	Type      TaskType
	Data      []byte
	CreatedAt time.Time
	Timeout   time.Duration
}

// TaskResult is the implant's response
type TaskResult struct {
	TaskID      [16]byte
	Status      uint8 // 0=success, 1=error, 2=timeout
	Data        []byte
	CompletedAt time.Time
}
