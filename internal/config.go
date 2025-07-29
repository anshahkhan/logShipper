package internal

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

type Config struct {
	OrgID         string   `yaml:"org_id"`
	LogTypes      []string `yaml:"log_types"`
	EventPatterns []string `yaml:"event_id_patterns"` // ← renamed from EventIDs
	IntervalSec   int      `yaml:"interval_sec"`
	ServerIP      string   `yaml:"server_ip"`
	Port          string   `yaml:"port"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	return &cfg, nil
}
