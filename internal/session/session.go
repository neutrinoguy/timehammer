// Package session provides NTP session recording and replay
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/pkg/ntpcore"
)

// SessionEvent represents a single event in a session
type SessionEvent struct {
	Timestamp    time.Time   `json:"timestamp"`
	Type         string      `json:"type"` // "request", "response", "upstream_query", "upstream_response"
	ClientAddr   string      `json:"client_addr,omitempty"`
	UpstreamAddr string      `json:"upstream_addr,omitempty"`
	PacketData   []byte      `json:"packet_data"`
	ParsedPacket *PacketInfo `json:"parsed_packet,omitempty"`
	AttackMode   string      `json:"attack_mode,omitempty"`
	Notes        string      `json:"notes,omitempty"`
}

// PacketInfo is a human-readable packet representation
type PacketInfo struct {
	LeapIndicator uint8  `json:"leap_indicator"`
	Version       uint8  `json:"version"`
	Mode          string `json:"mode"`
	Stratum       uint8  `json:"stratum"`
	Poll          int8   `json:"poll"`
	Precision     int8   `json:"precision"`
	ReferenceID   string `json:"reference_id"`
	TransmitTime  string `json:"transmit_time"`
	IsKoD         bool   `json:"is_kod,omitempty"`
	KoDCode       string `json:"kod_code,omitempty"`
}

// Session represents a recording session
type Session struct {
	ID          string         `json:"id"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     time.Time      `json:"end_time,omitempty"`
	Description string         `json:"description,omitempty"`
	Events      []SessionEvent `json:"events"`
	Stats       SessionStats   `json:"stats"`
}

// SessionStats contains session statistics
type SessionStats struct {
	TotalRequests   int           `json:"total_requests"`
	TotalResponses  int           `json:"total_responses"`
	UniqueClients   int           `json:"unique_clients"`
	UpstreamQueries int           `json:"upstream_queries"`
	AttacksExecuted int           `json:"attacks_executed"`
	AvgResponseTime time.Duration `json:"avg_response_time"`
}

// SessionRecorder handles session recording
type SessionRecorder struct {
	mu            sync.RWMutex
	active        bool
	session       *Session
	clientMap     map[string]bool
	responseTimes []time.Duration
}

// Global recorder instance
var globalRecorder *SessionRecorder
var recorderOnce sync.Once

// GetRecorder returns the global session recorder
func GetRecorder() *SessionRecorder {
	recorderOnce.Do(func() {
		globalRecorder = &SessionRecorder{
			clientMap: make(map[string]bool),
		}
	})
	return globalRecorder
}

// StartRecording starts a new recording session
func (r *SessionRecorder) StartRecording(description string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.active {
		return fmt.Errorf("recording already in progress")
	}

	r.session = &Session{
		ID:          fmt.Sprintf("session_%d", time.Now().Unix()),
		StartTime:   time.Now(),
		Description: description,
		Events:      make([]SessionEvent, 0),
		Stats:       SessionStats{},
	}
	r.clientMap = make(map[string]bool)
	r.responseTimes = make([]time.Duration, 0)
	r.active = true

	return nil
}

// StopRecording stops the current recording and saves it
func (r *SessionRecorder) StopRecording() (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return nil, fmt.Errorf("no recording in progress")
	}

	r.session.EndTime = time.Now()
	r.session.Stats.UniqueClients = len(r.clientMap)

	// Calculate average response time
	if len(r.responseTimes) > 0 {
		var total time.Duration
		for _, t := range r.responseTimes {
			total += t
		}
		r.session.Stats.AvgResponseTime = total / time.Duration(len(r.responseTimes))
	}

	// Save session to file
	if err := r.saveSession(); err != nil {
		return nil, err
	}

	session := r.session
	r.active = false
	r.session = nil

	return session, nil
}

// IsRecording returns whether recording is active
func (r *SessionRecorder) IsRecording() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// RecordClientRequest records an incoming client request
func (r *SessionRecorder) RecordClientRequest(clientAddr string, packet *ntpcore.NTPPacket, attackMode string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return
	}

	r.clientMap[clientAddr] = true
	r.session.Stats.TotalRequests++

	if attackMode != "" {
		r.session.Stats.AttacksExecuted++
	}

	event := SessionEvent{
		Timestamp:    time.Now(),
		Type:         "request",
		ClientAddr:   clientAddr,
		PacketData:   packet.Bytes(),
		ParsedPacket: packetToInfo(packet),
		AttackMode:   attackMode,
	}

	r.session.Events = append(r.session.Events, event)
}

// RecordClientResponse records an outgoing response
func (r *SessionRecorder) RecordClientResponse(clientAddr string, packet *ntpcore.NTPPacket, responseTime time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return
	}

	r.session.Stats.TotalResponses++
	r.responseTimes = append(r.responseTimes, responseTime)

	event := SessionEvent{
		Timestamp:    time.Now(),
		Type:         "response",
		ClientAddr:   clientAddr,
		PacketData:   packet.Bytes(),
		ParsedPacket: packetToInfo(packet),
	}

	r.session.Events = append(r.session.Events, event)
}

// RecordUpstreamQuery records an upstream NTP query
func (r *SessionRecorder) RecordUpstreamQuery(upstreamAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return
	}

	r.session.Stats.UpstreamQueries++

	event := SessionEvent{
		Timestamp:    time.Now(),
		Type:         "upstream_query",
		UpstreamAddr: upstreamAddr,
	}

	r.session.Events = append(r.session.Events, event)
}

// RecordUpstreamResponse records an upstream NTP response
func (r *SessionRecorder) RecordUpstreamResponse(upstreamAddr string, packet *ntpcore.NTPPacket) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return
	}

	event := SessionEvent{
		Timestamp:    time.Now(),
		Type:         "upstream_response",
		UpstreamAddr: upstreamAddr,
		PacketData:   packet.Bytes(),
		ParsedPacket: packetToInfo(packet),
	}

	r.session.Events = append(r.session.Events, event)
}

// saveSession saves the session to a file
func (r *SessionRecorder) saveSession() error {
	dataDir, err := config.GetDataDir()
	if err != nil {
		return err
	}

	sessionPath := filepath.Join(dataDir, config.SessionDirName, r.session.ID+".json")
	data, err := json.MarshalIndent(r.session, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sessionPath, data, 0644)
}

// ListSessions returns a list of saved sessions
func ListSessions() ([]SessionSummary, error) {
	dataDir, err := config.GetDataDir()
	if err != nil {
		return nil, err
	}

	sessionDir := filepath.Join(dataDir, config.SessionDirName)
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []SessionSummary{}, nil
		}
		return nil, err
	}

	var sessions []SessionSummary
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Load just the header info
		sessionPath := filepath.Join(sessionDir, entry.Name())
		data, err := os.ReadFile(sessionPath)
		if err != nil {
			continue
		}

		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		sessions = append(sessions, SessionSummary{
			ID:          session.ID,
			StartTime:   session.StartTime,
			EndTime:     session.EndTime,
			Description: session.Description,
			EventCount:  len(session.Events),
			Stats:       session.Stats,
		})
	}

	return sessions, nil
}

// SessionSummary provides a summary of a session
type SessionSummary struct {
	ID          string       `json:"id"`
	StartTime   time.Time    `json:"start_time"`
	EndTime     time.Time    `json:"end_time"`
	Description string       `json:"description"`
	EventCount  int          `json:"event_count"`
	Stats       SessionStats `json:"stats"`
}

// LoadSession loads a session from disk
func LoadSession(id string) (*Session, error) {
	dataDir, err := config.GetDataDir()
	if err != nil {
		return nil, err
	}

	sessionPath := filepath.Join(dataDir, config.SessionDirName, id+".json")
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// DeleteSession deletes a session file
func DeleteSession(id string) error {
	dataDir, err := config.GetDataDir()
	if err != nil {
		return err
	}

	sessionPath := filepath.Join(dataDir, config.SessionDirName, id+".json")
	return os.Remove(sessionPath)
}

// packetToInfo converts an NTP packet to human-readable info
func packetToInfo(p *ntpcore.NTPPacket) *PacketInfo {
	if p == nil {
		return nil
	}

	info := &PacketInfo{
		LeapIndicator: p.LeapIndicator,
		Version:       p.Version,
		Mode:          p.GetModeString(),
		Stratum:       p.Stratum,
		Poll:          p.Poll,
		Precision:     p.Precision,
		TransmitTime:  p.GetTransmitTime().Format(time.RFC3339),
	}

	// Check for KoD
	kod := p.GetKissOfDeathCode()
	if kod != "" {
		info.IsKoD = true
		info.KoDCode = kod
	}

	// Reference ID as string (for stratum 0-1 it's ASCII, otherwise IP)
	if p.Stratum <= 1 {
		bytes := []byte{
			byte(p.ReferenceID >> 24),
			byte(p.ReferenceID >> 16),
			byte(p.ReferenceID >> 8),
			byte(p.ReferenceID),
		}
		info.ReferenceID = string(bytes)
	} else {
		info.ReferenceID = fmt.Sprintf("%d.%d.%d.%d",
			(p.ReferenceID>>24)&0xFF,
			(p.ReferenceID>>16)&0xFF,
			(p.ReferenceID>>8)&0xFF,
			p.ReferenceID&0xFF)
	}

	return info
}

// GetCurrentSession returns the current session info (if recording)
func (r *SessionRecorder) GetCurrentSession() *SessionSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.active || r.session == nil {
		return nil
	}

	return &SessionSummary{
		ID:          r.session.ID,
		StartTime:   r.session.StartTime,
		Description: r.session.Description,
		EventCount:  len(r.session.Events),
		Stats:       r.session.Stats,
	}
}
