package operator

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewCLI(t *testing.T) {
	onList := func() []string { return []string{"abc", "def"} }
	onTask := func(id string, t uint8, d []byte, timeout int) (interface{}, error) {
		return map[string]string{"id": id}, nil
	}
	cli := NewCLI(onList, onTask)
	if cli == nil {
		t.Fatal("NewCLI returned nil")
	}
	if cli.onList == nil || cli.onTask == nil {
		t.Fatal("callbacks not set")
	}
}

func TestCLIOnList(t *testing.T) {
	sessions := []string{"session-1", "session-2"}
	onList := func() []string { return sessions }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		return nil, nil
	}
	cli := NewCLI(onList, onTask)
	result := cli.onList()
	if len(result) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(result))
	}
	if result[0] != "session-1" {
		t.Errorf("unexpected: %s", result[0])
	}
}

func TestCLIOnTask(t *testing.T) {
	var calledTaskType uint8
	onList := func() []string { return nil }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		calledTaskType = tp
		return map[string]string{"ok": "true"}, nil
	}
	cli := NewCLI(onList, onTask)
	result, err := cli.onTask("test-session", 7, []byte("sleep 60"), 30)
	if err != nil {
		t.Fatal(err)
	}
	if calledTaskType != 7 {
		t.Errorf("expected task type 7, got %d", calledTaskType)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func TestNewAPI(t *testing.T) {
	onList := func() []string { return []string{} }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		return nil, nil
	}
	api := NewAPI(":0", onList, onTask)
	if api == nil {
		t.Fatal("NewAPI returned nil")
	}
}

func TestAPIHandleSessions(t *testing.T) {
	onList := func() []string { return []string{"session-abc", "session-def"} }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		return nil, nil
	}
	api := NewAPI(":0", onList, onTask)

	req := httptest.NewRequest("GET", "/api/v1/sessions", nil)
	rec := httptest.NewRecorder()
	api.handleSessions(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session-abc") {
		t.Errorf("expected sessions in response, got: %s", rec.Body.String())
	}
}

func TestAPIHandleTask(t *testing.T) {
	onList := func() []string { return nil }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		return map[string]interface{}{"task_id": id, "type": tp}, nil
	}
	api := NewAPI(":0", onList, onTask)

	body := `{"session_id":"abc123","type":1,"data":"whoami","timeout":60}`
	req := httptest.NewRequest("POST", "/api/v1/task", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleTask(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIHandleTaskBadJSON(t *testing.T) {
	onList := func() []string { return nil }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		return nil, nil
	}
	api := NewAPI(":0", onList, onTask)

	req := httptest.NewRequest("POST", "/api/v1/task", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleTask(rec, req)

	if rec.Code != 400 {
		t.Errorf("expected 400 for bad JSON, got %d", rec.Code)
	}
}

func TestAPIHandleTaskDefaultTimeout(t *testing.T) {
	var receivedTimeout int
	onList := func() []string { return nil }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		receivedTimeout = to
		return nil, nil
	}
	api := NewAPI(":0", onList, onTask)

	body := `{"session_id":"test","type":3,"data":"/etc/passwd","timeout":0}`
	req := httptest.NewRequest("POST", "/api/v1/task", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleTask(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if receivedTimeout != 60 {
		t.Errorf("expected default timeout 60, got %d", receivedTimeout)
	}
}

func TestAPIHandleTaskMaxTimeout(t *testing.T) {
	var receivedTimeout int
	onList := func() []string { return nil }
	onTask := func(id string, tp uint8, d []byte, to int) (interface{}, error) {
		receivedTimeout = to
		return nil, nil
	}
	api := NewAPI(":0", onList, onTask)

	body := `{"session_id":"test","type":5,"data":"move","timeout":9999}`
	req := httptest.NewRequest("POST", "/api/v1/task", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleTask(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if receivedTimeout != 3600 {
		t.Errorf("expected capped timeout 3600, got %d", receivedTimeout)
	}
}
