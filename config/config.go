package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/gophish/gophish/logger"
)

// AdminServer represents the Admin server configuration details.
type AdminServer struct {
	ListenURL            string   `json:"listen_url"`
	UseTLS               bool     `json:"use_tls"`
	CertPath             string   `json:"cert_path"`
	KeyPath              string   `json:"key_path"`
	CSRFKey              string   `json:"csrf_key"`
	AllowedInternalHosts []string `json:"allowed_internal_hosts"`
	TrustedOrigins       []string `json:"trusted_origins"`
}

// PhishServer represents the Phish server configuration details.
type PhishServer struct {
	ListenURL string `json:"listen_url"`
	UseTLS    bool   `json:"use_tls"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
}

// Config holds the overall configuration for the application.
type Config struct {
	AdminConf      AdminServer `json:"admin_server"`
	PhishConf      PhishServer `json:"phish_server"`
	DBName         string      `json:"db_name"`
	DBPath         string      `json:"db_path"`
	DBSSLCaPath    string      `json:"db_sslca_path"`
	MigrationsPath string      `json:"migrations_prefix"`
	TestFlag       bool        `json:"test_flag"`
	ContactAddress string      `json:"contact_address"`
	Logging        *log.Config `json:"logging"`
}

// Version contains the current gophish version
var Version = ""

// ServerName is the server type returned in the transparency response.
const ServerName = "gophish"

// LoadConfig loads and parses the configuration from the specified file path.
// It performs validation and applies default values where appropriate.
func LoadConfig(filePath string) (*Config, error) {
	// Open the config file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %q: %w", filePath, err)
	}
	defer file.Close()

	// Decode JSON directly from the file stream
	decoder := json.NewDecoder(file)
	cfg := &Config{}
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config JSON: %w", err)
	}

	// Initialize Logging config if missing
	if cfg.Logging == nil {
		cfg.Logging = &log.Config{}
	}

	// Clean and join migration path with DBName to prevent path issues
	cfg.MigrationsPath = filepath.Clean(cfg.MigrationsPath)
	if cfg.DBName != "" {
		cfg.MigrationsPath = filepath.Join(cfg.MigrationsPath, cfg.DBName)
	}

	// Explicitly disable test flag regardless of config file content
	cfg.TestFlag = false

	// Optional: Validate critical fields to catch config errors early
	if cfg.AdminConf.ListenURL == "" {
		return nil, fmt.Errorf("admin_server.listen_url cannot be empty")
	}
	if cfg.PhishConf.ListenURL == "" {
		return nil, fmt.Errorf("phish_server.listen_url cannot be empty")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("db_path cannot be empty")
	}

	return cfg, nil
}
