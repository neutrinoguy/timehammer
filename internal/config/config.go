// Package config handles configuration management for TimeHammer
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	ConfigFileName = "config.yaml"
	DataDirName    = ".timehammer"
	LogFileName    = "timehammer.log"
	SessionDirName = "sessions"
	ExportDirName  = "exports"
)

// Config represents the main configuration structure
type Config struct {
	mu sync.RWMutex `yaml:"-"`

	// Server settings
	Server ServerConfig `yaml:"server"`

	// Upstream NTP servers
	Upstream UpstreamConfig `yaml:"upstream"`

	// Security testing mode
	Security SecurityConfig `yaml:"security"`

	// Logging settings
	Logging LoggingConfig `yaml:"logging"`

	// Attack presets
	AttackPresets []AttackPreset `yaml:"attack_presets"`
}

// ServerConfig holds server-specific settings
type ServerConfig struct {
	// Network interface to bind to (empty = all interfaces)
	Interface string `yaml:"interface"`

	// Port to listen on (default: 123)
	Port int `yaml:"port"`

	// Alternative port for unprivileged mode
	AltPort int `yaml:"alt_port"`

	// Use alternative port if standard port fails
	UseAltPortOnFail bool `yaml:"use_alt_port_on_fail"`

	// Maximum concurrent clients
	MaxClients int `yaml:"max_clients"`

	// NTP version to advertise
	NTPVersion int `yaml:"ntp_version"`

	// Stratum level to report
	Stratum int `yaml:"stratum"`

	// Enable SNTP mode (simplified responses)
	SNTPMode bool `yaml:"sntp_mode"`
}

// UpstreamConfig holds upstream NTP server settings
type UpstreamConfig struct {
	// List of upstream servers
	Servers []UpstreamServer `yaml:"servers"`

	// Sync interval in seconds
	SyncInterval int `yaml:"sync_interval"`

	// Timeout for upstream queries in seconds
	Timeout int `yaml:"timeout"`

	// Number of retry attempts
	Retries int `yaml:"retries"`
}

// UpstreamServer represents a single upstream NTP server
type UpstreamServer struct {
	// Server address (hostname or IP)
	Address string `yaml:"address"`

	// Port (default: 123)
	Port int `yaml:"port"`

	// Priority (lower = higher priority)
	Priority int `yaml:"priority"`

	// Enabled status
	Enabled bool `yaml:"enabled"`
}

// SecurityConfig holds security testing mode settings
type SecurityConfig struct {
	// Enable security testing mode
	Enabled bool `yaml:"enabled"`

	// Active attack type
	ActiveAttack string `yaml:"active_attack"`

	// Time spoofing settings
	TimeSpoofing TimeSpoofingConfig `yaml:"time_spoofing"`

	// Time drift settings
	TimeDrift TimeDriftConfig `yaml:"time_drift"`

	// Kiss-of-Death settings
	KissOfDeath KissOfDeathConfig `yaml:"kiss_of_death"`

	// Stratum attack settings
	StratumAttack StratumAttackConfig `yaml:"stratum_attack"`

	// Leap second settings
	LeapSecond LeapSecondConfig `yaml:"leap_second"`

	// Rollover attack settings
	Rollover RolloverConfig `yaml:"rollover"`

	// Clock step settings
	ClockStep ClockStepConfig `yaml:"clock_step"`
}

// TimeSpoofingConfig for time spoofing attack
type TimeSpoofingConfig struct {
	Enabled    bool   `yaml:"enabled"`
	OffsetSecs int64  `yaml:"offset_secs"` // Positive = future, Negative = past
	CustomTime string `yaml:"custom_time"` // RFC3339 format, overrides offset
}

// TimeDriftConfig for gradual time drift attack
type TimeDriftConfig struct {
	Enabled     bool    `yaml:"enabled"`
	DriftPerSec float64 `yaml:"drift_per_sec"` // Seconds to drift per second
	MaxDrift    float64 `yaml:"max_drift"`     // Maximum total drift in seconds
	Direction   string  `yaml:"direction"`     // "forward" or "backward"
}

// KissOfDeathConfig for KoD attack
type KissOfDeathConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Code     string `yaml:"code"`     // DENY, RATE, RSTR, etc.
	Interval int    `yaml:"interval"` // Send KoD every N requests (0 = always)
}

// StratumAttackConfig for stratum manipulation
type StratumAttackConfig struct {
	Enabled     bool `yaml:"enabled"`
	FakeStratum int  `yaml:"fake_stratum"` // 0-15, lower = more authoritative
}

// LeapSecondConfig for leap second injection
type LeapSecondConfig struct {
	Enabled       bool `yaml:"enabled"`
	LeapIndicator int  `yaml:"leap_indicator"` // 1 = +1 sec, 2 = -1 sec, 3 = alarm
}

// RolloverConfig for timestamp rollover attack
type RolloverConfig struct {
	Enabled    bool   `yaml:"enabled"`
	TargetYear int    `yaml:"target_year"` // e.g., 2038, 2036 (NTP rollover)
	Mode       string `yaml:"mode"`        // "y2k38", "ntp_era", "custom"
}

// ClockStepConfig for sudden clock step attack
type ClockStepConfig struct {
	Enabled  bool  `yaml:"enabled"`
	StepSecs int64 `yaml:"step_secs"` // Sudden jump in seconds
	Interval int   `yaml:"interval"`  // Apply step every N requests
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	// Log level (debug, info, warn, error)
	Level string `yaml:"level"`

	// Log to file
	LogToFile bool `yaml:"log_to_file"`

	// Log upstream requests
	LogUpstream bool `yaml:"log_upstream"`

	// Log downstream requests
	LogDownstream bool `yaml:"log_downstream"`

	// Enable client fingerprinting
	ClientFingerprint bool `yaml:"client_fingerprint"`

	// Session recording
	RecordSessions bool `yaml:"record_sessions"`

	// Maximum log entries to keep in memory
	MaxLogEntries int `yaml:"max_log_entries"`
}

// AttackPreset represents a pre-configured attack scenario
type AttackPreset struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Attack      string                 `yaml:"attack"`
	Config      map[string]interface{} `yaml:"config"`
}

// DefaultConfig returns a new Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Interface:        "",
			Port:             123,
			AltPort:          1123,
			UseAltPortOnFail: true,
			MaxClients:       100,
			NTPVersion:       4,
			Stratum:          2,
			SNTPMode:         false,
		},
		Upstream: UpstreamConfig{
			Servers: []UpstreamServer{
				{Address: "time.google.com", Port: 123, Priority: 1, Enabled: true},
				{Address: "time.cloudflare.com", Port: 123, Priority: 2, Enabled: true},
				{Address: "pool.ntp.org", Port: 123, Priority: 3, Enabled: true},
			},
			SyncInterval: 60,
			Timeout:      5,
			Retries:      3,
		},
		Security: SecurityConfig{
			Enabled:      false,
			ActiveAttack: "",
			TimeSpoofing: TimeSpoofingConfig{
				Enabled:    false,
				OffsetSecs: 3600, // 1 hour
			},
			TimeDrift: TimeDriftConfig{
				Enabled:     false,
				DriftPerSec: 0.001,
				MaxDrift:    60,
				Direction:   "forward",
			},
			KissOfDeath: KissOfDeathConfig{
				Enabled:  false,
				Code:     "DENY",
				Interval: 0,
			},
			StratumAttack: StratumAttackConfig{
				Enabled:     false,
				FakeStratum: 1,
			},
			LeapSecond: LeapSecondConfig{
				Enabled:       false,
				LeapIndicator: 1,
			},
			Rollover: RolloverConfig{
				Enabled:    false,
				TargetYear: 2038,
				Mode:       "y2k38",
			},
			ClockStep: ClockStepConfig{
				Enabled:  false,
				StepSecs: 3600,
				Interval: 5,
			},
		},
		Logging: LoggingConfig{
			Level:             "info",
			LogToFile:         true,
			LogUpstream:       true,
			LogDownstream:     true,
			ClientFingerprint: true,
			RecordSessions:    true,
			MaxLogEntries:     1000,
		},
		AttackPresets: []AttackPreset{
			{
				Name:        "Y2K38 Test",
				Description: "Test for Year 2038 problem (Unix timestamp overflow)",
				Attack:      "rollover",
				Config: map[string]interface{}{
					"target_year": 2038,
					"mode":        "y2k38",
				},
			},
			{
				Name:        "NTP Era Rollover",
				Description: "Test for NTP Era 1 rollover (February 2036)",
				Attack:      "rollover",
				Config: map[string]interface{}{
					"target_year": 2036,
					"mode":        "ntp_era",
				},
			},
			{
				Name:        "Gradual Drift",
				Description: "Slowly drift time to evade detection",
				Attack:      "time_drift",
				Config: map[string]interface{}{
					"drift_per_sec": 0.001,
					"max_drift":     300,
					"direction":     "forward",
				},
			},
			{
				Name:        "Instant Future",
				Description: "Jump 1 year into the future (certificate expiry test)",
				Attack:      "time_spoofing",
				Config: map[string]interface{}{
					"offset_secs": 31536000,
				},
			},
			{
				Name:        "Clock Skew Stress",
				Description: "Sudden large time jumps every 5 requests",
				Attack:      "clock_step",
				Config: map[string]interface{}{
					"step_secs": 86400,
					"interval":  5,
				},
			},
			{
				Name:        "DoS via KoD",
				Description: "Send Kiss-of-Death DENY packets to disable sync",
				Attack:      "kiss_of_death",
				Config: map[string]interface{}{
					"code":     "DENY",
					"interval": 0,
				},
			},
		},
	}
}

// GetDataDir returns the data directory path
func GetDataDir() (string, error) {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	dataDir := filepath.Join(cwd, DataDirName)
	return dataDir, nil
}

// EnsureDataDir creates the data directory if it doesn't exist
func EnsureDataDir() (string, error) {
	dataDir, err := GetDataDir()
	if err != nil {
		return "", err
	}

	// Create main data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create subdirectories
	subdirs := []string{SessionDirName, ExportDirName}
	for _, subdir := range subdirs {
		path := filepath.Join(dataDir, subdir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return "", fmt.Errorf("failed to create %s directory: %w", subdir, err)
		}
	}

	return dataDir, nil
}

// GetConfigPath returns the path to the config file
func GetConfigPath() (string, error) {
	dataDir, err := GetDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, ConfigFileName), nil
}

// Load loads configuration from file
func Load() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config
		cfg := DefaultConfig()
		if err := cfg.Save(); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
		return cfg, nil
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig() // Start with defaults
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// Save saves configuration to file
func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Ensure data directory exists
	if _, err := EnsureDataDir(); err != nil {
		return err
	}

	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Add header comment
	header := []byte("# TimeHammer Configuration File\n# Edit with care - invalid YAML will prevent startup\n# Use the TUI editor for safer editing\n\n")
	data = append(header, data...)

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetYAML returns the config as YAML string
func (c *Config) GetYAML() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// UpdateFromYAML updates the config from a YAML string
func (c *Config) UpdateFromYAML(yamlStr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	newCfg := DefaultConfig()
	if err := yaml.Unmarshal([]byte(yamlStr), newCfg); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	// Copy new values
	c.Server = newCfg.Server
	c.Upstream = newCfg.Upstream
	c.Security = newCfg.Security
	c.Logging = newCfg.Logging
	c.AttackPresets = newCfg.AttackPresets

	return nil
}

// GetActiveUpstreams returns list of enabled upstream servers sorted by priority
func (c *Config) GetActiveUpstreams() []UpstreamServer {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var active []UpstreamServer
	for _, s := range c.Upstream.Servers {
		if s.Enabled {
			if s.Port == 0 {
				s.Port = 123
			}
			active = append(active, s)
		}
	}
	return active
}

// GetOSInfo returns OS-specific information
func GetOSInfo() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// GetPortConflictHelp returns OS-specific commands to check/free port
func GetPortConflictHelp(port int) string {
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf(`⚠️  Port %d is in use. To free it on macOS:

1. Find the process:
   sudo lsof -i :%d

2. Stop the process (replace PID):
   sudo kill -9 <PID>

3. Or if it's the system NTP service:
   sudo launchctl unload /System/Library/LaunchDaemons/org.ntp.ntpd.plist

⚠️  WARNING: Do NOT run this on production systems!`, port, port)

	case "linux":
		return fmt.Sprintf(`⚠️  Port %d is in use. To free it on Linux:

1. Find the process:
   sudo ss -tulpn | grep :%d
   # or
   sudo netstat -tulpn | grep :%d

2. Stop the process (replace PID):
   sudo kill -9 <PID>

3. Or if it's systemd-timesyncd:
   sudo systemctl stop systemd-timesyncd

4. Or if it's ntpd:
   sudo systemctl stop ntp
   # or
   sudo systemctl stop ntpd

⚠️  WARNING: Do NOT run this on production systems!`, port, port, port)

	case "windows":
		return fmt.Sprintf(`⚠️  Port %d is in use. To free it on Windows:

1. Find the process (run as Administrator):
   netstat -ano | findstr :%d

2. Find process name by PID:
   tasklist | findstr <PID>

3. Stop the process:
   taskkill /PID <PID> /F

4. Or stop Windows Time service:
   net stop w32time

⚠️  WARNING: Do NOT run this on production systems!`, port, port)

	default:
		return fmt.Sprintf("Port %d is in use. Please check your system documentation for freeing ports.", port)
	}
}
