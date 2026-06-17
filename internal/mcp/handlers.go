package mcp

import (
	"fmt"
	"sync"
)

// ToolHandler is the function signature for MCP tool implementations.
type ToolHandler func(args map[string]interface{}) (interface{}, error)

// HandlerRegistry maps tool names to their handler functions.
type HandlerRegistry struct {
	mu       sync.RWMutex
	handlers map[string]ToolHandler
}

// NewHandlerRegistry creates an empty handler registry.
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{handlers: make(map[string]ToolHandler)}
}

// Register associates a tool name with its handler function.
func (hr *HandlerRegistry) Register(name string, handler ToolHandler) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	hr.handlers[name] = handler
}

// Call invokes the handler for the named tool with the given arguments.
func (hr *HandlerRegistry) Call(name string, args map[string]interface{}) (interface{}, error) {
	hr.mu.RLock()
	handler, ok := hr.handlers[name]
	hr.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	return handler(args)
}

// Global callback hooks — set by main.go at startup to wire the MCP tools to
// the actual Fortress engine.
var (
	OnStatus        func() map[string]interface{}
	OnListThreats   func(limit int) []map[string]interface{}
	OnBlockIP       func(ip string, duration int) error
	OnUnblockIP     func(ip string) error
	OnScanTarget    func(target string, deep bool) map[string]interface{}
	OnCounterstrike func(ip string) map[string]interface{}
	OnSwarmStatus   func() map[string]interface{}
	OnIntelLookup   func(ip string) map[string]interface{}
	OnToggleMode    func(aggressive bool) map[string]interface{}
)

func handleStatus(args map[string]interface{}) (interface{}, error) {
	if OnStatus == nil {
		return map[string]string{"status": "no callback registered"}, nil
	}
	return OnStatus(), nil
}

func handleListThreats(args map[string]interface{}) (interface{}, error) {
	limit := 10
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}
	if OnListThreats == nil {
		return []map[string]interface{}{}, nil
	}
	return OnListThreats(limit), nil
}

func handleBlockIP(args map[string]interface{}) (interface{}, error) {
	ip, _ := args["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	duration := 1800
	if d, ok := args["duration"].(float64); ok {
		duration = int(d)
	}
	if OnBlockIP == nil {
		return map[string]string{"status": "no callback"}, nil
	}
	err := OnBlockIP(ip, duration)
	if err != nil {
		return nil, err
	}
	return map[string]string{"status": "blocked", "ip": ip}, nil
}

func handleUnblockIP(args map[string]interface{}) (interface{}, error) {
	ip, _ := args["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if OnUnblockIP == nil {
		return map[string]string{"status": "no callback"}, nil
	}
	err := OnUnblockIP(ip)
	if err != nil {
		return nil, err
	}
	return map[string]string{"status": "unblocked", "ip": ip}, nil
}

func handleScanTarget(args map[string]interface{}) (interface{}, error) {
	target, _ := args["target"].(string)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	deep := false
	if d, ok := args["deep"].(bool); ok {
		deep = d
	}
	if OnScanTarget == nil {
		return map[string]string{"status": "no callback"}, nil
	}
	return OnScanTarget(target, deep), nil
}

func handleCounterstrike(args map[string]interface{}) (interface{}, error) {
	ip, _ := args["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if OnCounterstrike == nil {
		return map[string]string{"status": "no callback"}, nil
	}
	return OnCounterstrike(ip), nil
}

func handleSwarmStatus(args map[string]interface{}) (interface{}, error) {
	if OnSwarmStatus == nil {
		return map[string]string{"peers": "0"}, nil
	}
	return OnSwarmStatus(), nil
}

func handleIntelLookup(args map[string]interface{}) (interface{}, error) {
	ip, _ := args["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if OnIntelLookup == nil {
		return map[string]string{"status": "no callback"}, nil
	}
	return OnIntelLookup(ip), nil
}

func handleToggleMode(args map[string]interface{}) (interface{}, error) {
	aggressive, _ := args["aggressive"].(bool)
	if OnToggleMode == nil {
		return map[string]string{"status": "no callback"}, nil
	}
	return OnToggleMode(aggressive), nil
}
