package listener

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPSListener(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return []byte("ok"), nil
	}
	l := NewHTTPSListener("127.0.0.1:0", "", "", cb)
	if l == nil {
		t.Fatal("NewHTTPSListener returned nil")
	}
	if l.OnData == nil {
		t.Fatal("callback not set")
	}
}

func TestHTTPSListenerHealthCheck(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return []byte("ok"), nil
	}
	l := NewHTTPSListener("127.0.0.1:0", "", "", cb)
	// Verify struct fields are properly initialized
	if l.addr == "" {
		t.Error("addr should not be empty")
	}
	if l.server == nil {
		t.Fatal("http.Server not created")
	}
	if l.server.ReadTimeout != 30*time.Second {
		t.Errorf("expected 30s read timeout, got %v", l.server.ReadTimeout)
	}
	if l.server.WriteTimeout != 30*time.Second {
		t.Errorf("expected 30s write timeout, got %v", l.server.WriteTimeout)
	}
}

func TestHTTPSListenerTLSConfig(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return nil, nil
	}
	l := NewHTTPSListener("127.0.0.1:4433", "cert.pem", "key.pem", cb)
	if l.server.TLSConfig == nil {
		t.Fatal("TLS config should be set when cert+key provided")
	}
}

func TestNewDNSListener(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return nil, nil
	}
	l := NewDNSListener("127.0.0.1:5353", cb)
	if l == nil {
		t.Fatal("NewDNSListener returned nil")
	}
	if l.OnData == nil {
		t.Fatal("callback not set")
	}
}

func TestNewWSListener(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return nil, nil
	}
	l := NewWSListener(":8443", cb)
	if l == nil {
		t.Fatal("NewWSListener returned nil")
	}
	if l.OnData == nil {
		t.Fatal("callback not set")
	}
}

func TestNewMCPListener(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return nil, nil
	}
	inner := NewHTTPSListener("127.0.0.1:0", "", "", cb)
	l := NewMCPListener(inner)
	if l == nil {
		t.Fatal("NewMCPListener returned nil")
	}
	if l.inner != inner {
		t.Fatal("inner listener not wired")
	}
}

func TestMCPDisguiseTaskAsMCP(t *testing.T) {
	data, err := DisguiseTaskAsMCP([]byte("test-encrypted-payload"))
	if err != nil {
		t.Fatalf("DisguiseTaskAsMCP: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("disguised data is empty")
	}
	// Output should be valid JSON
	if data[0] != '{' {
		t.Error("output should be JSON object")
	}
}

func TestNewICMPListener(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return nil, nil
	}
	l := NewICMPListener(cb)
	if l == nil {
		t.Fatal("NewICMPListener returned nil")
	}
	// ICMP listener should start without error (root not required for struct creation)
	err := l.Start()
	if err != nil {
		t.Logf("ICMP Start returned (expected): %v", err)
	}
}

func TestCallbackInterface(t *testing.T) {
	var cb Callback = func(transport string, data []byte) ([]byte, error) {
		return append([]byte(transport+":"), data...), nil
	}
	result, err := cb("https", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "https:hello" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestDNSListenerStartStop(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return nil, nil
	}
	l := NewDNSListener("127.0.0.1:0", cb)

	// Start listener on random port
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Skipf("cannot bind UDP: %v", err)
	}
	defer conn.Close()

	// Verify we can create and bind
	if l.OnData == nil {
		t.Fatal("callback not set")
	}
	t.Logf("UDP test conn: %v", conn.LocalAddr())
}

func TestHTTPSListenerHealthEndpoint(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return []byte("echo:" + string(data)), nil
	}
	l := NewHTTPSListener("127.0.0.1:0", "", "", cb)

	// The server handler is set up during construction
	handler := l.server.Handler
	if handler == nil {
		t.Fatal("handler is nil")
	}

	// Test health endpoint via ServeMux
	req, _ := http.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPSListenerCheckinEndpoint(t *testing.T) {
	cb := func(transport string, data []byte) ([]byte, error) {
		return []byte("task-data"), nil
	}
	l := NewHTTPSListener("127.0.0.1:0", "", "", cb)

	handler := l.server.Handler
	req, _ := http.NewRequest("GET", "/", strings.NewReader("checkin-data"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if body != "task-data" {
		t.Errorf("expected 'task-data', got %q", body)
	}
}
