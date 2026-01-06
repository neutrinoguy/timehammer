// Package ntp provides upstream NTP client functionality
package ntp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/logger"
)

// UpstreamClient manages connections to upstream NTP servers
type UpstreamClient struct {
	mu          sync.RWMutex
	cfg         *config.Config
	log         *logger.Logger
	currentTime time.Time
	clockOffset time.Duration
	lastSync    time.Time
	syncStatus  SyncStatus
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// SyncStatus represents the upstream sync status
type SyncStatus struct {
	Synchronized bool          `json:"synchronized"`
	ActiveServer string        `json:"active_server"`
	Stratum      int           `json:"stratum"`
	Offset       time.Duration `json:"offset"`
	RTT          time.Duration `json:"rtt"`
	LastSync     time.Time     `json:"last_sync"`
	LastError    string        `json:"last_error,omitempty"`
}

// NewUpstreamClient creates a new upstream NTP client
func NewUpstreamClient(cfg *config.Config) *UpstreamClient {
	return &UpstreamClient{
		cfg:      cfg,
		log:      logger.GetLogger(),
		stopChan: make(chan struct{}),
		syncStatus: SyncStatus{
			Synchronized: false,
		},
	}
}

// Start begins the upstream sync loop
func (c *UpstreamClient) Start() {
	c.wg.Add(1)
	go c.syncLoop()
}

// Stop stops the upstream sync
func (c *UpstreamClient) Stop() {
	close(c.stopChan)
	c.wg.Wait()
}

// syncLoop runs the periodic sync
func (c *UpstreamClient) syncLoop() {
	defer c.wg.Done()

	// Initial sync
	c.syncNow()

	interval := time.Duration(c.cfg.Upstream.SyncInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.syncNow()
		case <-c.stopChan:
			return
		}
	}
}

// syncNow performs an immediate sync with upstream servers
func (c *UpstreamClient) syncNow() {
	servers := c.cfg.GetActiveUpstreams()
	if len(servers) == 0 {
		c.log.Warn("UPSTREAM", "No upstream servers configured")
		c.mu.Lock()
		c.syncStatus.Synchronized = false
		c.syncStatus.LastError = "No upstream servers configured"
		c.mu.Unlock()
		return
	}

	// Try servers in order of priority
	for _, server := range servers {
		addr := fmt.Sprintf("%s:%d", server.Address, server.Port)

		c.log.Debugf("UPSTREAM", "Querying upstream server: %s", addr)

		response, err := c.queryServer(server.Address)
		if err != nil {
			c.log.Warnf("UPSTREAM", "Failed to query %s: %v", addr, err)
			c.log.LogUpstreamRequest(addr, false, 0, 0)
			continue
		}

		// Success!
		c.mu.Lock()
		c.clockOffset = response.ClockOffset
		c.currentTime = time.Now().Add(response.ClockOffset)
		c.lastSync = time.Now()
		c.syncStatus = SyncStatus{
			Synchronized: true,
			ActiveServer: server.Address,
			Stratum:      int(response.Stratum),
			Offset:       response.ClockOffset,
			RTT:          response.RTT,
			LastSync:     time.Now(),
		}
		c.mu.Unlock()

		c.log.Infof("UPSTREAM", "Synced with %s (stratum %d, offset %v, RTT %v)",
			server.Address, response.Stratum, response.ClockOffset, response.RTT)
		c.log.LogUpstreamRequest(addr, true, response.RTT, response.ClockOffset)

		return
	}

	// All servers failed
	c.mu.Lock()
	c.syncStatus.Synchronized = false
	c.syncStatus.LastError = "All upstream servers failed"
	c.mu.Unlock()
	c.log.Error("UPSTREAM", "Failed to sync with any upstream server")
}

// queryServer queries a single NTP server
func (c *UpstreamClient) queryServer(addr string) (*ntp.Response, error) {
	options := ntp.QueryOptions{
		Timeout: time.Duration(c.cfg.Upstream.Timeout) * time.Second,
		TTL:     128,
	}

	var lastErr error
	for i := 0; i < c.cfg.Upstream.Retries; i++ {
		response, err := ntp.QueryWithOptions(addr, options)
		if err != nil {
			lastErr = err
			continue
		}

		// Validate response
		if err := response.Validate(); err != nil {
			lastErr = err
			continue
		}

		return response, nil
	}

	return nil, lastErr
}

// GetCurrentTime returns the current synchronized time
func (c *UpstreamClient) GetCurrentTime() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.syncStatus.Synchronized {
		// Fall back to local time if not synchronized
		return time.Now()
	}

	// Calculate time based on last sync and offset
	elapsed := time.Since(c.lastSync)
	return c.lastSync.Add(elapsed).Add(c.clockOffset)
}

// GetSyncStatus returns the current sync status
func (c *UpstreamClient) GetSyncStatus() SyncStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.syncStatus
}

// GetStratum returns the stratum to report (upstream stratum + 1)
func (c *UpstreamClient) GetStratum() uint8 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.syncStatus.Synchronized {
		return 16 // Unsynchronized
	}

	stratum := c.syncStatus.Stratum + 1
	if stratum > 15 {
		stratum = 15
	}
	return uint8(stratum)
}

// GetReferenceID returns the reference ID to use
func (c *UpstreamClient) GetReferenceID() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.syncStatus.Synchronized || c.syncStatus.ActiveServer == "" {
		return 0
	}

	// Try to resolve the active server to an IP
	ips, err := net.LookupIP(c.syncStatus.ActiveServer)
	if err != nil || len(ips) == 0 {
		return 0
	}

	// Use the first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		}
	}

	return 0
}

// ForceSync triggers an immediate sync
func (c *UpstreamClient) ForceSync() {
	go c.syncNow()
}

// UpdateConfig updates the client configuration
func (c *UpstreamClient) UpdateConfig(cfg *config.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
}
