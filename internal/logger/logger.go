// Package logger provides structured logging for TimeHammer
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
)

// LogLevel represents log severity
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// LogColor returns ANSI color code for the level
func (l LogLevel) LogColor() string {
	switch l {
	case LevelDebug:
		return "\033[36m" // Cyan
	case LevelInfo:
		return "\033[32m" // Green
	case LevelWarn:
		return "\033[33m" // Yellow
	case LevelError:
		return "\033[31m" // Red
	default:
		return "\033[0m"
	}
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       LogLevel               `json:"level"`
	LevelStr    string                 `json:"level_str"`
	Category    string                 `json:"category"`
	Message     string                 `json:"message"`
	ClientIP    string                 `json:"client_ip,omitempty"`
	ClientPort  int                    `json:"client_port,omitempty"`
	UpstreamIP  string                 `json:"upstream_ip,omitempty"`
	Attack      string                 `json:"attack,omitempty"`
	Fingerprint *ClientFingerprint     `json:"fingerprint,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// ClientFingerprint represents NTP client identification
type ClientFingerprint struct {
	Version        int    `json:"version"`
	Mode           int    `json:"mode"`
	ModeString     string `json:"mode_string"`
	Stratum        int    `json:"stratum"`
	Poll           int    `json:"poll"`
	Precision      int    `json:"precision"`
	PossibleClient string `json:"possible_client,omitempty"`
}

// Logger is the main logger instance
type Logger struct {
	mu          sync.RWMutex
	entries     []LogEntry
	maxEntries  int
	level       LogLevel
	logToFile   bool
	fileHandle  *os.File
	subscribers []chan LogEntry
}

// Global logger instance
var globalLogger *Logger
var once sync.Once

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	once.Do(func() {
		globalLogger = &Logger{
			entries:     make([]LogEntry, 0),
			maxEntries:  1000,
			level:       LevelInfo,
			subscribers: make([]chan LogEntry, 0),
		}
	})
	return globalLogger
}

// Initialize sets up the logger with config
func (l *Logger) Initialize(cfg *config.Config) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.maxEntries = cfg.Logging.MaxLogEntries
	l.level = parseLevel(cfg.Logging.Level)
	l.logToFile = cfg.Logging.LogToFile

	if l.logToFile {
		dataDir, err := config.GetDataDir()
		if err != nil {
			return err
		}
		logPath := filepath.Join(dataDir, config.LogFileName)
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		l.fileHandle = f
	}

	return nil
}

// Close closes the logger
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileHandle != nil {
		l.fileHandle.Close()
	}

	for _, ch := range l.subscribers {
		close(ch)
	}
}

// Subscribe returns a channel that receives new log entries
func (l *Logger) Subscribe() chan LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := make(chan LogEntry, 100)
	l.subscribers = append(l.subscribers, ch)
	return ch
}

// Unsubscribe removes a subscription channel
func (l *Logger) Unsubscribe(ch chan LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for i, sub := range l.subscribers {
		if sub == ch {
			l.subscribers = append(l.subscribers[:i], l.subscribers[i+1:]...)
			break
		}
	}
}

// log is the internal logging function
func (l *Logger) log(level LogLevel, category, message string, extra map[string]interface{}) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		LevelStr:  level.String(),
		Category:  category,
		Message:   message,
		Extra:     extra,
	}

	l.mu.Lock()
	// Add to in-memory buffer
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxEntries {
		l.entries = l.entries[1:]
	}

	// Write to file
	if l.fileHandle != nil {
		jsonLine, _ := json.Marshal(entry)
		l.fileHandle.Write(append(jsonLine, '\n'))
	}

	// Notify subscribers
	for _, ch := range l.subscribers {
		select {
		case ch <- entry:
		default:
			// Channel full, skip
		}
	}
	l.mu.Unlock()
}

// Debug logs a debug message
func (l *Logger) Debug(category, message string) {
	l.log(LevelDebug, category, message, nil)
}

// Info logs an info message
func (l *Logger) Info(category, message string) {
	l.log(LevelInfo, category, message, nil)
}

// Warn logs a warning message
func (l *Logger) Warn(category, message string) {
	l.log(LevelWarn, category, message, nil)
}

// Error logs an error message
func (l *Logger) Error(category, message string) {
	l.log(LevelError, category, message, nil)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(category, format string, args ...interface{}) {
	l.Debug(category, fmt.Sprintf(format, args...))
}

// Infof logs a formatted info message
func (l *Logger) Infof(category, format string, args ...interface{}) {
	l.Info(category, fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(category, format string, args ...interface{}) {
	l.Warn(category, fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(category, format string, args ...interface{}) {
	l.Error(category, fmt.Sprintf(format, args...))
}

// LogClientRequest logs an NTP client request with fingerprinting
func (l *Logger) LogClientRequest(clientIP string, clientPort int, fp *ClientFingerprint, attack string) {
	entry := LogEntry{
		Timestamp:   time.Now(),
		Level:       LevelInfo,
		LevelStr:    LevelInfo.String(),
		Category:    "CLIENT",
		Message:     fmt.Sprintf("Request from %s:%d", clientIP, clientPort),
		ClientIP:    clientIP,
		ClientPort:  clientPort,
		Fingerprint: fp,
		Attack:      attack,
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxEntries {
		l.entries = l.entries[1:]
	}

	if l.fileHandle != nil {
		jsonLine, _ := json.Marshal(entry)
		l.fileHandle.Write(append(jsonLine, '\n'))
	}

	for _, ch := range l.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
	l.mu.Unlock()
}

// LogUpstreamRequest logs an upstream NTP query
func (l *Logger) LogUpstreamRequest(upstreamIP string, success bool, rtt time.Duration, offset time.Duration) {
	status := "success"
	level := LevelInfo
	if !success {
		status = "failed"
		level = LevelWarn
	}

	entry := LogEntry{
		Timestamp:  time.Now(),
		Level:      level,
		LevelStr:   level.String(),
		Category:   "UPSTREAM",
		Message:    fmt.Sprintf("Query to %s: %s (RTT: %v, Offset: %v)", upstreamIP, status, rtt, offset),
		UpstreamIP: upstreamIP,
		Extra: map[string]interface{}{
			"success": success,
			"rtt_ms":  rtt.Milliseconds(),
			"offset":  offset.String(),
		},
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxEntries {
		l.entries = l.entries[1:]
	}

	if l.fileHandle != nil {
		jsonLine, _ := json.Marshal(entry)
		l.fileHandle.Write(append(jsonLine, '\n'))
	}

	for _, ch := range l.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
	l.mu.Unlock()
}

// LogAttack logs a security attack being executed
func (l *Logger) LogAttack(attackType, target, details string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     LevelWarn,
		LevelStr:  LevelWarn.String(),
		Category:  "ATTACK",
		Message:   fmt.Sprintf("[%s] %s: %s", attackType, target, details),
		Attack:    attackType,
		ClientIP:  target,
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxEntries {
		l.entries = l.entries[1:]
	}

	if l.fileHandle != nil {
		jsonLine, _ := json.Marshal(entry)
		l.fileHandle.Write(append(jsonLine, '\n'))
	}

	for _, ch := range l.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
	l.mu.Unlock()
}

// GetEntries returns recent log entries
func (l *Logger) GetEntries(count int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if count <= 0 || count > len(l.entries) {
		count = len(l.entries)
	}

	start := len(l.entries) - count
	if start < 0 {
		start = 0
	}

	result := make([]LogEntry, count)
	copy(result, l.entries[start:])
	return result
}

// GetAllEntries returns all log entries
func (l *Logger) GetAllEntries() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]LogEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// ClearEntries clears all in-memory log entries
func (l *Logger) ClearEntries() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make([]LogEntry, 0)
}

// ExportJSON exports logs to a JSON file
func (l *Logger) ExportJSON(filename string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	dataDir, err := config.GetDataDir()
	if err != nil {
		return err
	}

	exportPath := filepath.Join(dataDir, config.ExportDirName, filename)
	data, err := json.MarshalIndent(l.entries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(exportPath, data, 0644)
}

// ExportCSV exports logs to a CSV file
func (l *Logger) ExportCSV(filename string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	dataDir, err := config.GetDataDir()
	if err != nil {
		return err
	}

	exportPath := filepath.Join(dataDir, config.ExportDirName, filename)
	f, err := os.Create(exportPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header
	f.WriteString("Timestamp,Level,Category,Message,ClientIP,ClientPort,UpstreamIP,Attack,ClientVersion,ClientMode\n")

	for _, entry := range l.entries {
		clientVersion := ""
		clientMode := ""
		if entry.Fingerprint != nil {
			clientVersion = fmt.Sprintf("%d", entry.Fingerprint.Version)
			clientMode = entry.Fingerprint.ModeString
		}

		line := fmt.Sprintf("%s,%s,%s,\"%s\",%s,%d,%s,%s,%s,%s\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.LevelStr,
			entry.Category,
			entry.Message,
			entry.ClientIP,
			entry.ClientPort,
			entry.UpstreamIP,
			entry.Attack,
			clientVersion,
			clientMode,
		)
		f.WriteString(line)
	}

	return nil
}

// parseLevel parses a string log level
func parseLevel(s string) LogLevel {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// FormatEntry formats a log entry for display
func FormatEntry(entry LogEntry) string {
	timestamp := entry.Timestamp.Format("15:04:05")
	color := entry.Level.LogColor()
	reset := "\033[0m"

	return fmt.Sprintf("%s%s %s[%s]%s %s",
		color, timestamp, reset,
		entry.Category,
		reset, entry.Message)
}

// FormatEntryPlain formats a log entry without colors
func FormatEntryPlain(entry LogEntry) string {
	timestamp := entry.Timestamp.Format("15:04:05")
	return fmt.Sprintf("%s [%s] [%s] %s",
		timestamp, entry.LevelStr, entry.Category, entry.Message)
}
