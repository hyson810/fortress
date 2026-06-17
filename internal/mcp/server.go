package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// Server is the MCP stdio JSON-RPC server for AI agent control.
type Server struct {
	mu       sync.Mutex
	reader   *bufio.Reader
	writer   io.Writer
	tools    *ToolRegistry
	handlers *HandlerRegistry
	running  bool
}

// NewServer creates a new MCP server reading from stdin and writing to stdout.
func NewServer() *Server {
	return &Server{
		reader:   bufio.NewReader(os.Stdin),
		writer:   os.Stdout,
		tools:    NewToolRegistry(),
		handlers: NewHandlerRegistry(),
	}
}

// Serve starts the MCP JSON-RPC loop on stdio. It blocks until EOF or Stop is
// called.
func (s *Server) Serve() error {
	s.running = true
	log.Println("[mcp] MCP server started on stdio")
	for s.running {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("mcp: read: %w", err)
		}
		s.handleMessage(line)
	}
	return nil
}

func (s *Server) handleMessage(data []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		s.sendError(nil, -32700, "Parse error")
		return
	}
	method, _ := msg["method"].(string)
	id, _ := msg["id"]

	switch method {
	case "initialize":
		s.sendResult(id, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "fortress-v6",
				"version": "6.0.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{},
			},
		})
	case "tools/list":
		s.sendResult(id, map[string]interface{}{
			"tools": s.tools.List(),
		})
	case "tools/call":
		params, _ := msg["params"].(map[string]interface{})
		toolName, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]interface{})
		result, err := s.handlers.Call(toolName, args)
		if err != nil {
			s.sendError(id, -32000, err.Error())
		} else {
			s.sendResult(id, result)
		}
	case "notifications/initialized":
		// Client is ready — no response needed
	default:
		s.sendError(id, -32601, fmt.Sprintf("Method not found: %s", method))
	}
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "result": result,
	}
	data, _ := json.Marshal(resp)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writer.Write(append(data, '\n'))
}

func (s *Server) sendError(id interface{}, code int, message string) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]interface{}{
			"code": code, "message": message,
		},
	}
	data, _ := json.Marshal(resp)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writer.Write(append(data, '\n'))
}

// RegisterTool registers a tool definition and its handler.
func (s *Server) RegisterTool(name, description string, schema map[string]interface{}, handler ToolHandler) {
	s.tools.Register(name, description, schema)
	s.handlers.Register(name, handler)
}

// Stop signals the server to stop accepting new messages.
func (s *Server) Stop() {
	s.running = false
}
