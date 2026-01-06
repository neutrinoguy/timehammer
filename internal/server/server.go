// Package server implements the NTP server
package server

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neutrinoguy/timehammer/internal/attacks"
	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/logger"
	"github.com/neutrinoguy/timehammer/internal/ntp"
	"github.com/neutrinoguy/timehammer/internal/session"
	"github.com/neutrinoguy/timehammer/pkg/ntpcore"
)

// Server is the main NTP server
type Server struct {
	mu           sync.RWMutex
	cfg          *config.Config
	log          *logger.Logger
	upstream     *ntp.UpstreamClient
	attackEngine *attacks.AttackEngine
	recorder     *session.SessionRecorder
	conn         *net.UDPConn
	running      atomic.Bool
	stopChan     chan struct{}
	wg           sync.WaitGroup

	// Stats
	stats ServerStats
}

// ServerStats holds server statistics
type ServerStats struct {
	mu              sync.RWMutex
	StartTime       time.Time
	TotalRequests   uint64
	TotalResponses  uint64
	ActiveClients   map[string]time.Time
	ErrorCount      uint64
	AttacksExecuted uint64
}

// ClientInfo represents connected client information
type ClientInfo struct {
	Address      string
	LastSeen     time.Time
	RequestCount int
	Version      int
	Mode         string
}

// NewServer creates a new NTP server
func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg:          cfg,
		log:          logger.GetLogger(),
		upstream:     ntp.NewUpstreamClient(cfg),
		attackEngine: attacks.NewAttackEngine(cfg),
		recorder:     session.GetRecorder(),
		stopChan:     make(chan struct{}),
		stats: ServerStats{
			StartTime:     time.Now(),
			ActiveClients: make(map[string]time.Time),
		},
	}
}

// Start starts the NTP server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running.Load() {
		return fmt.Errorf("server already running")
	}

	// Determine which port to use
	port := s.cfg.Server.Port
	iface := s.cfg.Server.Interface

	// Build address
	addr := fmt.Sprintf("%s:%d", iface, port)

	// Try to bind
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		// If standard port fails and alt port is enabled, try alt port
		if s.cfg.Server.UseAltPortOnFail && port == s.cfg.Server.Port {
			s.log.Warnf("SERVER", "Failed to bind to port %d, trying alt port %d", port, s.cfg.Server.AltPort)

			altAddr := fmt.Sprintf("%s:%d", iface, s.cfg.Server.AltPort)
			altUdpAddr, _ := net.ResolveUDPAddr("udp", altAddr)

			conn, err = net.ListenUDP("udp", altUdpAddr)
			if err != nil {
				// Provide helpful error message
				s.log.Error("SERVER", config.GetPortConflictHelp(s.cfg.Server.AltPort))
				return fmt.Errorf("failed to bind to port %d or %d: %w", s.cfg.Server.Port, s.cfg.Server.AltPort, err)
			}
			port = s.cfg.Server.AltPort
		} else {
			s.log.Error("SERVER", config.GetPortConflictHelp(port))
			return fmt.Errorf("failed to bind to port %d: %w", port, err)
		}
	}

	s.conn = conn
	s.running.Store(true)
	s.stats.StartTime = time.Now()

	// Start upstream client
	s.upstream.Start()

	// Start request handler
	s.wg.Add(1)
	go s.handleRequests()

	// Start client cleanup routine
	s.wg.Add(1)
	go s.cleanupClients()

	s.log.Infof("SERVER", "NTP server started on %s:%d", iface, port)
	if iface == "" {
		s.log.Info("SERVER", "Listening on all interfaces")
	}

	return nil
}

// Stop stops the NTP server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running.Load() {
		return fmt.Errorf("server not running")
	}

	// Signal stop
	close(s.stopChan)

	// Close connection
	if s.conn != nil {
		s.conn.Close()
	}

	// Stop upstream
	s.upstream.Stop()

	// Wait for goroutines
	s.wg.Wait()

	s.running.Store(false)
	s.log.Info("SERVER", "NTP server stopped")

	return nil
}

// handleRequests handles incoming NTP requests
func (s *Server) handleRequests() {
	defer s.wg.Done()

	buffer := make([]byte, 1024)

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		// Set read deadline to allow checking for stop
		s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, just retry
			}
			// Check if we're stopping
			select {
			case <-s.stopChan:
				return
			default:
				s.log.Errorf("SERVER", "Read error: %v", err)
				atomic.AddUint64(&s.stats.ErrorCount, 1)
				continue
			}
		}

		// Process request in goroutine for concurrency
		go s.processRequest(buffer[:n], clientAddr)
	}
}

// processRequest processes a single NTP request
func (s *Server) processRequest(data []byte, clientAddr *net.UDPAddr) {
	startTime := time.Now()
	clientStr := clientAddr.String()

	// Parse incoming packet
	packet, err := ntpcore.ParsePacket(data)
	if err != nil {
		s.log.Warnf("SERVER", "Invalid packet from %s: %v", clientStr, err)
		atomic.AddUint64(&s.stats.ErrorCount, 1)
		return
	}

	// Validate it's a client request
	if !packet.IsValidClientRequest() {
		s.log.Debugf("SERVER", "Non-client packet from %s (mode: %s)", clientStr, packet.GetModeString())
		return
	}

	// Update stats
	atomic.AddUint64(&s.stats.TotalRequests, 1)
	s.stats.mu.Lock()
	s.stats.ActiveClients[clientStr] = time.Now()
	s.stats.mu.Unlock()

	// Create fingerprint for logging
	fingerprint := &logger.ClientFingerprint{
		Version:    int(packet.Version),
		Mode:       int(packet.Mode),
		ModeString: packet.GetModeString(),
		Stratum:    int(packet.Stratum),
		Poll:       int(packet.Poll),
		Precision:  int(packet.Precision),
	}

	// Identify possible client implementation
	fingerprint.PossibleClient = identifyClient(packet)

	// Get current time from upstream
	currentTime := s.upstream.GetCurrentTime()
	receiveTime := time.Now()

	// Create response packet
	response := ntpcore.NewPacket()
	response.Version = packet.Version // Echo client's version
	response.Mode = ntpcore.ModeServer
	response.Stratum = s.upstream.GetStratum()
	response.Poll = packet.Poll
	response.Precision = -20 // ~1 microsecond

	// Set reference ID
	response.ReferenceID = s.upstream.GetReferenceID()

	// Set timestamps
	// Copy client's transmit time to our origin time
	response.SetOriginTime(packet.XmitTimeSec, packet.XmitTimeFrac)
	response.SetReceiveTime(receiveTime)
	response.SetReferenceTime(currentTime.Add(-time.Second))
	response.SetTransmitTime(time.Now())

	// Calculate root delay/dispersion
	syncStatus := s.upstream.GetSyncStatus()
	response.RootDelay = ntpcore.CalculateRootDelay(float64(syncStatus.RTT.Milliseconds()))
	response.RootDisp = ntpcore.CalculateRootDispersion(10) // 10ms dispersion

	// Check for security mode and apply attacks
	attackName := ""
	if s.attackEngine.IsEnabled() {
		response, attackName = s.attackEngine.ProcessPacket(response, clientStr, currentTime)
		if attackName != "" {
			atomic.AddUint64(&s.stats.AttacksExecuted, 1)
		}
	}

	// Record session if enabled
	if s.recorder.IsRecording() {
		s.recorder.RecordClientRequest(clientStr, packet, attackName)
		s.recorder.RecordClientResponse(clientStr, response, time.Since(startTime))
	}

	// Log the request
	s.log.LogClientRequest(clientAddr.IP.String(), clientAddr.Port, fingerprint, attackName)

	// Send response
	responseBytes := response.Bytes()
	_, err = s.conn.WriteToUDP(responseBytes, clientAddr)
	if err != nil {
		s.log.Errorf("SERVER", "Failed to send response to %s: %v", clientStr, err)
		atomic.AddUint64(&s.stats.ErrorCount, 1)
		return
	}

	atomic.AddUint64(&s.stats.TotalResponses, 1)

	// Log response
	if attackName != "" {
		s.log.Debugf("SERVER", "Sent response to %s with attack: %s", clientStr, attackName)
	} else {
		s.log.Debugf("SERVER", "Sent response to %s (time: %s)", clientStr, currentTime.Format(time.RFC3339))
	}
}

// cleanupClients removes stale clients from the active list
func (s *Server) cleanupClients() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.stats.mu.Lock()
			now := time.Now()
			for addr, lastSeen := range s.stats.ActiveClients {
				if now.Sub(lastSeen) > 5*time.Minute {
					delete(s.stats.ActiveClients, addr)
				}
			}
			s.stats.mu.Unlock()
		case <-s.stopChan:
			return
		}
	}
}

// identifyClient attempts to identify the NTP client implementation
func identifyClient(packet *ntpcore.NTPPacket) string {
	// Common patterns for client identification
	// This is a heuristic based on typical client behaviors

	if packet.Version == 3 {
		if packet.Poll == 6 {
			return "Windows W32Time (possible)"
		}
		return "NTPv3 Client"
	}

	if packet.Version == 4 {
		switch packet.Poll {
		case 6:
			return "ntpd/chrony (likely)"
		case 7:
			return "systemd-timesyncd (possible)"
		case 10:
			return "macOS sntp (possible)"
		default:
			return "NTPv4 Client"
		}
	}

	return "Unknown"
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	return s.running.Load()
}

// GetStats returns server statistics
func (s *Server) GetStats() Stats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return Stats{
		Uptime:          time.Since(s.stats.StartTime),
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		TotalResponses:  atomic.LoadUint64(&s.stats.TotalResponses),
		ActiveClients:   len(s.stats.ActiveClients),
		ErrorCount:      atomic.LoadUint64(&s.stats.ErrorCount),
		AttacksExecuted: atomic.LoadUint64(&s.stats.AttacksExecuted),
	}
}

// Stats is the public stats structure
type Stats struct {
	Uptime          time.Duration
	TotalRequests   uint64
	TotalResponses  uint64
	ActiveClients   int
	ErrorCount      uint64
	AttacksExecuted uint64
}

// GetActiveClients returns list of active clients
func (s *Server) GetActiveClients() []ClientInfo {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	clients := make([]ClientInfo, 0, len(s.stats.ActiveClients))
	for addr, lastSeen := range s.stats.ActiveClients {
		clients = append(clients, ClientInfo{
			Address:  addr,
			LastSeen: lastSeen,
		})
	}
	return clients
}

// GetUpstreamStatus returns upstream sync status
func (s *Server) GetUpstreamStatus() ntp.SyncStatus {
	return s.upstream.GetSyncStatus()
}

// ForceUpstreamSync triggers an immediate upstream sync
func (s *Server) ForceUpstreamSync() {
	s.upstream.ForceSync()
}

// GetAttackEngine returns the attack engine
func (s *Server) GetAttackEngine() *attacks.AttackEngine {
	return s.attackEngine
}

// UpdateConfig updates the server configuration
func (s *Server) UpdateConfig(cfg *config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.upstream.UpdateConfig(cfg)
	s.attackEngine.UpdateConfig(cfg)
}

// GetListenAddress returns the current listen address
func (s *Server) GetListenAddress() string {
	if s.conn == nil {
		return "not bound"
	}
	return s.conn.LocalAddr().String()
}
