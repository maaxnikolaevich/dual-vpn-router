package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the dual-vpn-router configuration
type Config struct {
	DNS     DNSConfig     `yaml:"dns"`
	Routing RoutingConfig `yaml:"routing"`
	VPNs    []VPNConfig   `yaml:"vpns"`
}

// DNSConfig represents DNS settings
type DNSConfig struct {
	ListenAddr string   `yaml:"listen_addr"`
	Fallback   []string `yaml:"fallback"`
	Domains    []Domain `yaml:"domains"`
}

// Domain represents a domain with its DNS servers
type Domain struct {
	Name   string   `yaml:"name"`
	Servers []string `yaml:"servers"`
}

// RoutingConfig represents routing settings
type RoutingConfig struct {
	CorpTableID int      `yaml:"corp_table_id"`
	CorpNetworks []string `yaml:"corp_networks"`
}

// VPNConfig represents a VPN connection
type VPNConfig struct {
	Name        string `yaml:"name"`
	Interface   string `yaml:"interface"`
	AutoDetect  bool   `yaml:"auto_detect"`
	Type        string `yaml:"type"`
}

// DefaultConfig returns default configuration with placeholders
func DefaultConfig() *Config {
	return &Config{
		DNS: DNSConfig{
			ListenAddr: "127.0.0.1:53",
			Fallback:   []string{"8.8.8.8", "8.8.4.4"},
			Domains: []Domain{
				{
					Name:    "corporate.example.com",
					Servers: []string{"192.168.1.1", "192.168.1.2"},
				},
			},
		},
		Routing: RoutingConfig{
			CorpTableID: 200,
			CorpNetworks: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
		VPNs: []VPNConfig{
			{
				Name:       "corporate",
				Interface:  "tun0",
				AutoDetect: true,
				Type:       "corporate",
			},
			{
				Name:       "global",
				Interface:  "wg0",
				AutoDetect: true,
				Type:       "global",
			},
		},
	}
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save saves configuration to file
func Save(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
