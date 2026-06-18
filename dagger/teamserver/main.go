package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("teamserver shutting down")
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
