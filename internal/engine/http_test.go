package engine

import (
	"testing"

	"github.com/fortress/v6/internal/config"
)

func TestSQLiDetection(t *testing.T) {
	h := NewHttpInspector(config.Default())
	payload := []byte("GET /search?q=1' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n")
	threats := h.Feed("10.0.0.1", "10.0.0.2", 12345, 80, payload)
	for _, th := range threats {
		if th.Type == "SQL注入攻击" {
			t.Log("SQLi detected")
			return
		}
	}
	t.Error("expected SQL injection detection")
}

func TestXSSDetection(t *testing.T) {
	h := NewHttpInspector(config.Default())
	payload := []byte("GET /page?msg=<script>alert(1)</script> HTTP/1.1\r\n\r\n")
	threats := h.Feed("10.0.0.1", "10.0.0.2", 12345, 80, payload)
	for _, th := range threats {
		if th.Type == "XSS攻击" {
			t.Log("XSS detected")
			return
		}
	}
	t.Error("expected XSS detection")
}

func TestPathTraversalDetection(t *testing.T) {
	h := NewHttpInspector(config.Default())
	payload := []byte("GET /../../../etc/passwd HTTP/1.1\r\n\r\n")
	threats := h.Feed("10.0.0.1", "10.0.0.2", 12345, 80, payload)
	for _, th := range threats {
		if th.Type == "路径遍历攻击" {
			t.Log("Path traversal detected")
			return
		}
	}
	t.Error("expected path traversal detection")
}
