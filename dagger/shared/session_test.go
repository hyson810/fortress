package shared

import (
	"bytes"
	"testing"
)

func TestSessionEnvelopeRoundtrip(t *testing.T) {
	e := &SessionEnvelope{
		SessionID: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Seq:       42,
		Type:      1, // result
		Payload:   []byte("hello from implant"),
	}

	data, err := e.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	e2, err := UnmarshalEnvelope(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if e.SessionID != e2.SessionID {
		t.Error("session ID mismatch")
	}
	if e.Seq != e2.Seq {
		t.Error("seq mismatch")
	}
	if e.Type != e2.Type {
		t.Error("type mismatch")
	}
	if !bytes.Equal(e.Payload, e2.Payload) {
		t.Errorf("payload mismatch: got %q, want %q", e2.Payload, e.Payload)
	}
}

func TestUnmarshalEnvelopeUnderflow(t *testing.T) {
	_, err := UnmarshalEnvelope(bytes.NewReader([]byte{0, 1, 2}))
	if err == nil {
		t.Error("expected error on underflow")
	}
}

func TestUnmarshalEnvelopePayloadTooLarge(t *testing.T) {
	// Manually construct a header with payload > 10MB
	buf := make([]byte, 29)
	buf[24] = 1 // type
	buf[25] = 0  // payload length bytes
	buf[26] = 159
	buf[27] = 0
	buf[28] = 1 // 10485761 > 10MB

	_, err := UnmarshalEnvelope(bytes.NewReader(buf))
	if err == nil {
		t.Error("expected payload-too-large error")
	}
}

func TestTaskTypeValues(t *testing.T) {
	tests := []struct {
		name string
		val  TaskType
	}{
		{"None", TaskNone},
		{"Shell", TaskShell},
		{"Upload", TaskUpload},
		{"Download", TaskDownload},
		{"Inject", TaskInject},
		{"Lateral", TaskLateral},
		{"Persist", TaskPersist},
		{"Sleep", TaskSleep},
		{"Exit", TaskExit},
		{"Plugin", TaskPlugin},
		{"KeyRotate", TaskKeyRotate},
	}
	for _, tt := range tests {
		if tt.val > 10 {
			t.Errorf("%s should be <= 10, got %d", tt.name, tt.val)
		}
	}
}
