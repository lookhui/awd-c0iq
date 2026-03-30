package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"awd-h1m-pro/internal/util"

	"gopkg.in/yaml.v3"
)

const CurrentVersion = "1.0"

type ShellConfig struct {
	Port    string `yaml:"port" json:"port"`
	Pass    string `yaml:"pass" json:"pass"`
	Path    string `yaml:"path" json:"path"`
	File    string `yaml:"file" json:"file"`
	Method  string `yaml:"method" json:"method"`
	Query   string `yaml:"query" json:"query"`
	Payload string `yaml:"payload" json:"payload"`
	Timeout int64  `yaml:"timeout" json:"timeout"`
	Proxy   string `yaml:"proxy" json:"proxy"`
}

type SSHConfig struct {
	Host     string `yaml:"host" json:"host"`
	Port     string `yaml:"port" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Path     string `yaml:"path" json:"path"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host" json:"host"`
	Port     string `yaml:"port" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Name     string `yaml:"name" json:"name"`
}

type UndeadHorseConfig struct {
	URLPass  string `yaml:"urlPass" json:"urlPass"`
	Pass     string `yaml:"pass" json:"pass"`
	Filename string `yaml:"filename" json:"filename"`
}

type WormShellConfig struct {
	URLPass string `yaml:"urlPass" json:"urlPass"`
	Pass    string `yaml:"pass" json:"pass"`
}

type Config struct {
	Version     string            `yaml:"version" json:"version"`
	OwnIPs      string            `yaml:"ownIPs" json:"ownIPs"`
	Shell       ShellConfig       `yaml:"shell" json:"shell"`
	SSH         SSHConfig         `yaml:"ssh" json:"ssh"`
	Database    DatabaseConfig    `yaml:"database" json:"database"`
	UndeadHorse UndeadHorseConfig `yaml:"undeadHorse" json:"undeadHorse"`
	WormShell   WormShellConfig   `yaml:"wormShell" json:"wormShell"`
}

var (
	mu      sync.RWMutex
	current = DefaultConfig()
)

func DefaultConfig() *Config {
	return &Config{
		Version: CurrentVersion,
		Shell: ShellConfig{
			Port:    "80",
			Path:    "/",
			File:    "index.php",
			Method:  "POST",
			Payload: "php",
			Timeout: 5,
		},
		SSH: SSHConfig{
			Port: "22",
			Path: "/var/www/html",
		},
		Database: DatabaseConfig{
			Port: "3306",
		},
		UndeadHorse: UndeadHorseConfig{
			URLPass:  "pass",
			Pass:     "pass",
			Filename: "favicon.php",
		},
		WormShell: WormShellConfig{
			URLPass: "pass",
			Pass:    "pass",
		},
	}
}

func getConfigPath() string {
	return util.JoinExePath("config.yaml")
}

func ensureConfigExists() error {
	path := getConfigPath()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(path, nil, 0o644)
	}
	return nil
}

func InitConfig() error {
	if err := ensureConfigExists(); err != nil {
		return err
	}
	_, err := LoadConfig()
	return err
}

func LoadConfig() (*Config, error) {
	if err := ensureConfigExists(); err != nil {
		return nil, err
	}
	path := getConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}
	migrateIfNeeded(cfg)
	mu.Lock()
	current = cfg
	mu.Unlock()
	return Clone(), nil
}

func SaveConfig() error {
	mu.RLock()
	cfg := *current
	mu.RUnlock()
	migrateIfNeeded(&cfg)
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	if err := util.EnsureDir(filepath.Dir(getConfigPath())); err != nil {
		return err
	}
	if err := os.WriteFile(getConfigPath(), data, 0o644); err != nil {
		return err
	}
	mu.Lock()
	current = &cfg
	mu.Unlock()
	return nil
}

func Clone() *Config {
	mu.RLock()
	defer mu.RUnlock()
	copyValue := *current
	return &copyValue
}

func Update(fn func(cfg *Config)) error {
	mu.Lock()
	cfg := *current
	fn(&cfg)
	migrateIfNeeded(&cfg)
	current = &cfg
	mu.Unlock()
	return SaveConfig()
}

func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if cfg.Shell.Timeout <= 0 {
		cfg.Shell.Timeout = 5
	}
	if cfg.Shell.Method == "" {
		cfg.Shell.Method = "POST"
	}
	if cfg.Shell.Payload == "" {
		cfg.Shell.Payload = "php"
	}
	cfg.Shell.Payload = strings.ToLower(strings.TrimSpace(cfg.Shell.Payload))
	if cfg.Shell.Payload != "php" && cfg.Shell.Payload != "raw" {
		cfg.Shell.Payload = "php"
	}
	cfg.Shell.Query = strings.TrimSpace(cfg.Shell.Query)
	if cfg.Shell.Port == "" {
		cfg.Shell.Port = "80"
	}
	if cfg.SSH.Port == "" {
		cfg.SSH.Port = "22"
	}
	if cfg.Database.Port == "" {
		cfg.Database.Port = "3306"
	}
	return nil
}

func migrateIfNeeded(cfg *Config) {
	if cfg == nil {
		return
	}
	_ = ValidateConfig(cfg)
	if cfg.Version == "" {
		cfg.Version = CurrentVersion
	}
}
