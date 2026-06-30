package response

import (
	"testing"
)

func TestNewAlerter(t *testing.T) {
	a, err := NewAlerter(t.TempDir())
	if err != nil {
		t.Fatalf("NewAlerter returned error: %v", err)
	}
	if a == nil {
		t.Fatal("NewAlerter returned nil")
	}
	a.Close()
}

func TestAlert_Basic(t *testing.T) {
	a, _ := NewAlerter(t.TempDir())
	defer a.Close()

	a.Alert("10.0.0.1", "port scan detected", 0.85, AlertWarning)

	if c := a.Count(); c != 1 {
		t.Fatalf("expected count 1, got %d", c)
	}
}

func TestRecentAlerts(t *testing.T) {
	a, _ := NewAlerter(t.TempDir())
	defer a.Close()

	a.Alert("10.0.0.1", "alert one", 1.0, AlertInfo)
	a.Alert("10.0.0.2", "alert two", 2.0, AlertWarning)
	a.Alert("10.0.0.3", "alert three", 3.0, AlertCritical)

	alerts := a.RecentAlerts(10)
	if len(alerts) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(alerts))
	}
	if alerts[0].Message != "alert one" {
		t.Errorf("expected first alert message 'alert one', got %q", alerts[0].Message)
	}
	if alerts[2].Message != "alert three" {
		t.Errorf("expected third alert message 'alert three', got %q", alerts[2].Message)
	}
}

func TestRecentAlerts_Cap(t *testing.T) {
	a, _ := NewAlerter(t.TempDir())
	defer a.Close()

	for i := 0; i < 5; i++ {
		a.Alert("10.0.0.1", "alert", float64(i), AlertInfo)
	}

	alerts := a.RecentAlerts(2)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	// Most recent two should have scores 3.0 and 4.0
	if alerts[0].Score != 3.0 {
		t.Errorf("expected first recent alert score 3.0, got %f", alerts[0].Score)
	}
	if alerts[1].Score != 4.0 {
		t.Errorf("expected second recent alert score 4.0, got %f", alerts[1].Score)
	}
}

func TestAddWebhook(t *testing.T) {
	a, _ := NewAlerter(t.TempDir())
	defer a.Close()

	a.AddWebhook("https://hooks.example.com/alert")
	a.AddWebhook("https://hooks.example.com/alert2")

	wh := a.Webhooks()
	if len(wh) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(wh))
	}
	if wh[0] != "https://hooks.example.com/alert" {
		t.Errorf("expected first webhook URL, got %q", wh[0])
	}
	if wh[1] != "https://hooks.example.com/alert2" {
		t.Errorf("expected second webhook URL, got %q", wh[1])
	}
}

func TestCount(t *testing.T) {
	a, _ := NewAlerter(t.TempDir())
	defer a.Close()

	if c := a.Count(); c != 0 {
		t.Fatalf("expected initial count 0, got %d", c)
	}

	a.Alert("10.0.0.1", "first", 0.5, AlertInfo)
	a.Alert("10.0.0.2", "second", 0.8, AlertWarning)

	if c := a.Count(); c != 2 {
		t.Fatalf("expected count 2 after 2 alerts, got %d", c)
	}
}

func TestAlert_Levels(t *testing.T) {
	a, _ := NewAlerter(t.TempDir())
	defer a.Close()

	a.Alert("10.0.0.1", "info", 0.1, AlertInfo)
	a.Alert("10.0.0.2", "warning", 0.5, AlertWarning)
	a.Alert("10.0.0.3", "critical", 0.9, AlertCritical)

	alerts := a.RecentAlerts(10)
	if len(alerts) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(alerts))
	}

	if alerts[0].Level != AlertInfo {
		t.Errorf("expected AlertInfo (0), got %d", alerts[0].Level)
	}
	if alerts[0].Response != levelToString(AlertInfo) {
		t.Errorf("expected response %q, got %q", levelToString(AlertInfo), alerts[0].Response)
	}

	if alerts[1].Level != AlertWarning {
		t.Errorf("expected AlertWarning (1), got %d", alerts[1].Level)
	}
	if alerts[1].Response != levelToString(AlertWarning) {
		t.Errorf("expected response %q, got %q", levelToString(AlertWarning), alerts[1].Response)
	}

	if alerts[2].Level != AlertCritical {
		t.Errorf("expected AlertCritical (2), got %d", alerts[2].Level)
	}
	if alerts[2].Response != levelToString(AlertCritical) {
		t.Errorf("expected response %q, got %q", levelToString(AlertCritical), alerts[2].Response)
	}
}

func TestAlerter_Close(t *testing.T) {
	a, err := NewAlerter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Close should not panic
	a.Close()
	// Calling Close multiple times should also not panic
	a.Close()
}

func TestNotifyWebhooks_Empty(t *testing.T) {
	alert := Alert{
		IP:      "10.0.0.1",
		Message: "test",
		Score:   0.5,
		Level:   AlertInfo,
	}
	err := NotifyWebhooks(nil, alert)
	if err != nil {
		t.Fatalf("expected nil error for empty webhooks, got: %v", err)
	}

	err = NotifyWebhooks([]string{}, alert)
	if err != nil {
		t.Fatalf("expected nil error for empty webhooks slice, got: %v", err)
	}
}
