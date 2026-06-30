package dashboard

import (
	"encoding/json"
	"testing"
)

func TestThreatSummaryJSON(t *testing.T) {
	ts := ThreatSummary{
		IP:         "192.168.1.1",
		TotalScore: 85.5,
		Level:      "critical",
	}
	data, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded ThreatSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.IP != "192.168.1.1" || decoded.TotalScore != 85.5 {
		t.Fatalf("roundtrip broken: %+v", decoded)
	}
}

func TestWSMessageJSON(t *testing.T) {
	msg := WSMessage{Type: "test", Data: map[string]string{"key": "val"}}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded WSMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
}
