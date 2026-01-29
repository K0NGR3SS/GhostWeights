package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Regions      []string            `yaml:"regions"`
	Exclude      ExcludeConfig       `yaml:"exclude"`
	CustomPorts  []CustomPort        `yaml:"custom_ports"`
	DeepScan     bool                `yaml:"deep_scan"`
	OutputFormat string              `yaml:"output_format"`
	MinRisk      string              `yaml:"min_risk"`
	Slack        SlackConfig         `yaml:"slack"`
}

type ExcludeConfig struct {
	Instances []string          `yaml:"instances"`
	Tags      map[string]string `yaml:"tags"`
}

type CustomPort struct {
	Port        int32  `yaml:"port"`
	Name        string `yaml:"name"`
	Risk        string `yaml:"risk"`
	Description string `yaml:"description"`
}

type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.OutputFormat != "" && c.OutputFormat != "table" && c.OutputFormat != "json" && c.OutputFormat != "csv" {
		return fmt.Errorf("invalid output_format: %s", c.OutputFormat)
	}

	validRisks := map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	if c.MinRisk != "" && !validRisks[c.MinRisk] {
		return fmt.Errorf("invalid min_risk: %s", c.MinRisk)
	}

	return nil
}