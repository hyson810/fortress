package mcp

import "sync"

// ToolDefinition describes a single MCP tool exposed to the AI client.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolRegistry holds all registered tool definitions.
type ToolRegistry struct {
	mu    sync.RWMutex
	tools []ToolDefinition
}

// NewToolRegistry creates an empty tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{}
}

// Register adds a tool definition to the registry.
func (tr *ToolRegistry) Register(name, description string, schema map[string]interface{}) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.tools = append(tr.tools, ToolDefinition{
		Name: name, Description: description, InputSchema: schema,
	})
}

// List returns a copy of all registered tool definitions.
func (tr *ToolRegistry) List() []ToolDefinition {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	result := make([]ToolDefinition, len(tr.tools))
	copy(result, tr.tools)
	return result
}

// RegisterAllTools registers the complete set of Fortress V6 MCP tools on the
// given server instance.
func RegisterAllTools(s *Server) {
	s.RegisterTool("fortress_status", "Get Fortress system status and threat summary",
		map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		}, handleStatus)

	s.RegisterTool("fortress_list_threats", "List top tracked threat IPs with scores",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Max IPs to return",
					"default":     10,
				},
			},
		}, handleListThreats)

	s.RegisterTool("fortress_block_ip", "Block an IP address at the firewall/eBPF level",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "IP address to block",
				},
				"duration": map[string]interface{}{
					"type":        "integer",
					"description": "Block duration in seconds",
					"default":     1800,
				},
			},
			"required": []string{"ip"},
		}, handleBlockIP)

	s.RegisterTool("fortress_unblock_ip", "Remove an IP from the blocklist",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "IP to unblock",
				},
			},
			"required": []string{"ip"},
		}, handleUnblockIP)

	s.RegisterTool("fortress_scan_target", "Run Kali nmap+nuclei scan against a target",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"target": map[string]interface{}{
					"type":        "string",
					"description": "Target IP or hostname",
				},
				"deep": map[string]interface{}{
					"type":        "boolean",
					"description": "Deep scan (slower, more thorough)",
					"default":     false,
				},
			},
			"required": []string{"target"},
		}, handleScanTarget)

	s.RegisterTool("fortress_launch_counterstrike", "Launch counterstrike against an attacker IP",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "Target IP",
				},
			},
			"required": []string{"ip"},
		}, handleCounterstrike)

	s.RegisterTool("fortress_swarm_status", "Get swarm peer status",
		map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		}, handleSwarmStatus)

	s.RegisterTool("fortress_intel_lookup", "Look up threat intelligence for an IP",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "IP to investigate",
				},
			},
			"required": []string{"ip"},
		}, handleIntelLookup)

	s.RegisterTool("fortress_toggle_mode", "Toggle between normal and aggressive defense mode",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"aggressive": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable aggressive mode",
				},
			},
			"required": []string{"aggressive"},
		}, handleToggleMode)
}
