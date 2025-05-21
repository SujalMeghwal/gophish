package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	log "github.com/gophish/gophish/logger"
)

var validConfig = []byte(`{
  "admin_server": {
    "listen_url": "127.0.0.1:8443",
    "use_tls": true,
    "cert_path": "certs/admin.crt",
    "key_path": "certs/admin.key",
    "trusted_origins": [
      "https://admin.gophish.local"
    ]
  },
  "phish_server": {
    "listen_url": "0.0.0.0:8080",
    "use_tls": false,
    "cert_path": "certs/phish.crt",
    "key_path": "certs/phish.key"
  },
  "db_name": "sqlite3",
  "db_path": "data/gophish.db",
  "migrations_prefix": "db/migrations/",
  "contact_address": "admin@gophish.tld",
  "logging": {
    "filename": "logs/gophish.log",
    "level": "info"
  }
}`)

func createTempConfigFile(t *testing.T, content []byte) (string, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "gophish-config-*.json")
	if err != nil {
		t.Fatalf("unable to create temporary config file: %v", err)
	}

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("unable to write to temporary config file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("unable to close temporary config file: %v", err)
	}

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	return tmpFile.Name(), cleanup
}

func TestLoadConfig(t *testing.T) {
	configPath, cleanup := createTempConfigFile(t, validConfig)
	defer cleanup()

	conf, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	expected := &Config{}
	if err := json.Unmarshal(validConfig, expected); err != nil {
		t.Fatalf("error unmarshaling validConfig JSON: %v", err)
	}

	// Update expected according to post-load processing in LoadConfig
	expected.MigrationsPath = filepath.Join(expected.MigrationsPath, expected.DBName)
	expected.TestFlag = false
	if expected.AdminConf.CSRFKey == "" {
		// Explicitly set to empty string if missing in JSON
		expected.AdminConf.CSRFKey = ""
	}
	if expected.Logging == nil {
		expected.Logging = &log.Config{}
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("config mismatch:\nexpected: %#v\ngot: %#v", expected, conf)
	}

	// Check loading a non-existent config triggers an error
	_, err = LoadConfig("nonexistent_file.json")
	if err == nil {
		t.Fatalf("expected error when loading non-existent config file, but got none")
	}
}
