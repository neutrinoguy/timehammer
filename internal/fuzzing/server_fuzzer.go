// Package fuzzing implements NTP client/server fuzzing strategies and health probing
package fuzzing

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/logger"
	"github.com/neutrinoguy/timehammer/pkg/ntpcore"
)

// ServerFuzzer instruments and fuzzes a remote NTP/SNTP server
type ServerFuzzer struct {
	mu           sync.RWMutex
	cfg          *config.Config
	log          *logger.Logger
	running      bool
	cancel       context.CancelFunc
	stats        ServerFuzzerStats
	lastSentFuzz []byte
	lastFuzzDesc string
}

// ServerFuzzerStats holds statistics for server fuzzing operations
type ServerFuzzerStats struct {
	StartTime     time.Time `json:"start_time"`
	FuzzSent      uint64    `json:"fuzz_sent"`
	ProbesSent    uint64    `json:"probes_sent"`
	ProbeFailures uint64    `json:"probe_failures"`
	CrashesFound  uint64    `json:"crashes_found"`
	Status        string    `json:"status"`
}

// NewServerFuzzer creates a new remote NTP Server fuzzer instance
func NewServerFuzzer(cfg *config.Config) *ServerFuzzer {
	return &ServerFuzzer{
		cfg: cfg,
		log: logger.GetLogger(),
	}
}

// Start begins the server fuzzing and health probing loops
func (sf *ServerFuzzer) Start() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if sf.running {
		return fmt.Errorf("server fuzzer is already running")
	}

	target := sf.cfg.Security.ServerFuzzing.Target
	if target == "" {
		return fmt.Errorf("server fuzzing target address cannot be empty")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sf.cancel = cancel
	sf.running = true
	sf.stats = ServerFuzzerStats{
		StartTime: time.Now(),
		Status:    "Running",
	}

	sf.log.Infof("SERVER_FUZZER", "Starting NTP Server Fuzzing against target %s", target)

	go sf.runFuzzLoop(ctx)
	go sf.runHealthProbeLoop(ctx)

	return nil
}

// Stop halts server fuzzing
func (sf *ServerFuzzer) Stop() {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if !sf.running {
		return
	}

	if sf.cancel != nil {
		sf.cancel()
	}
	sf.running = false
	sf.stats.Status = "Stopped"
	sf.log.Info("SERVER_FUZZER", "NTP Server Fuzzing stopped")
}

// IsRunning checks if the server fuzzer is active
func (sf *ServerFuzzer) IsRunning() bool {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	return sf.running
}

// GetStats returns current server fuzzer stats
func (sf *ServerFuzzer) GetStats() ServerFuzzerStats {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	return sf.stats
}

func (sf *ServerFuzzer) runFuzzLoop(ctx context.Context) {
	intervalMs := sf.cfg.Security.ServerFuzzing.FuzzIntervalMs
	if intervalMs <= 0 {
		intervalMs = 200
	}

	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sf.sendFuzzedPacket()
		}
	}
}

func (sf *ServerFuzzer) sendFuzzedPacket() {
	sf.mu.Lock()
	target := sf.cfg.Security.ServerFuzzing.Target
	mode := sf.cfg.Security.ServerFuzzing.Mode
	sf.mu.Unlock()

	packet, desc := GenerateMutatedClientPacket(mode)
	rawBytes := packet.Bytes()

	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		sf.log.Errorf("SERVER_FUZZER", "Target resolve error: %v", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		sf.log.Errorf("SERVER_FUZZER", "UDP Dial error: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(rawBytes)
	if err != nil {
		sf.log.Errorf("SERVER_FUZZER", "Failed to send fuzzed packet: %v", err)
		return
	}

	sf.mu.Lock()
	sf.stats.FuzzSent++
	sf.lastSentFuzz = rawBytes
	sf.lastFuzzDesc = desc
	sf.mu.Unlock()
}

func (sf *ServerFuzzer) runHealthProbeLoop(ctx context.Context) {
	probeSec := sf.cfg.Security.ServerFuzzing.ProbeIntervalSec
	if probeSec <= 0 {
		probeSec = 2
	}

	ticker := time.NewTicker(time.Duration(probeSec) * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sf.mu.RLock()
			target := sf.cfg.Security.ServerFuzzing.Target
			maxFailures := sf.cfg.Security.ServerFuzzing.MaxProbeFailures
			lastPayload := sf.lastSentFuzz
			lastDesc := sf.lastFuzzDesc
			sf.mu.RUnlock()

			if maxFailures <= 0 {
				maxFailures = 3
			}

			sf.mu.Lock()
			sf.stats.ProbesSent++
			sf.mu.Unlock()

			responsive := sf.sendHealthProbe(target)
			if responsive {
				consecutiveFailures = 0
			} else {
				consecutiveFailures++
				sf.mu.Lock()
				sf.stats.ProbeFailures++
				sf.mu.Unlock()

				sf.log.Warnf("SERVER_FUZZER", "Health probe failure %d/%d for target %s", consecutiveFailures, maxFailures, target)

				if consecutiveFailures >= maxFailures {
					sf.log.Errorf("SERVER_FUZZER", "TARGET CRASH DETECTED: Remote server %s failed %d consecutive health probes after fuzz payload!", target, maxFailures)

					sf.mu.Lock()
					sf.stats.CrashesFound++
					sf.stats.Status = "Crash Detected"
					sf.mu.Unlock()

					// Save crash report
					report, err := SaveCrashReport("server_crash", target, lastDesc, lastPayload, nil, time.Duration(consecutiveFailures*probeSec)*time.Second)
					if err != nil {
						sf.log.Errorf("SERVER_FUZZER", "Failed to save crash report: %v", err)
					} else {
						sf.log.Infof("SERVER_FUZZER", "Recorded unique server crash report: %s", report.ID)
					}

					// Stop fuzzing after crash is recorded
					sf.Stop()
					return
				}
			}
		}
	}
}

func (sf *ServerFuzzer) sendHealthProbe(target string) bool {
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		return false
	}

	req := ntpcore.NewPacket()
	req.Mode = ntpcore.ModeClient
	req.SetTransmitTime(time.Now())

	_, err = conn.Write(req.Bytes())
	if err != nil {
		return false
	}

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	return err == nil && n >= ntpcore.NTPPacketMinSize
}

// GenerateMutatedClientPacket creates a mutated NTP Client packet based on strategy
func GenerateMutatedClientPacket(strategy string) (*ntpcore.NTPPacket, string) {
	packet := ntpcore.NewPacket()
	packet.Mode = ntpcore.ModeClient
	packet.SetTransmitTime(time.Now())

	mutation := rand.Intn(10)
	desc := "Mutated Client Request"

	switch mutation {
	case 0:
		packet.Version = uint8(rand.Intn(8))
		desc = fmt.Sprintf("Client Fuzz: Version %d", packet.Version)
	case 1:
		packet.Mode = uint8(rand.Intn(8))
		desc = fmt.Sprintf("Client Fuzz: Mode %d", packet.Mode)
	case 2:
		packet.Stratum = uint8(rand.Intn(255))
		desc = fmt.Sprintf("Client Fuzz: Stratum %d", packet.Stratum)
	case 3:
		packet.LeapIndicator = 3
		desc = "Client Fuzz: LI Alarm"
	case 4:
		packet.RecvTimeSec = 0xFFFFFFFF
		packet.RecvTimeFrac = 0xFFFFFFFF
		packet.XmitTimeSec = 0xFFFFFFFF
		packet.XmitTimeFrac = 0xFFFFFFFF
		desc = "Client Fuzz: Max Timestamps (0xFFFFFFFF)"
	case 5:
		packet.Poll = -128
		packet.Precision = 127
		desc = "Client Fuzz: Extremum Poll/Precision"
	case 6:
		packet.RootDelay = 0xFFFFFFFF
		packet.RootDisp = 0xFFFFFFFF
		desc = "Client Fuzz: Max Root Delay/Dispersion"
	case 7:
		packet.ReferenceID = 0x41414141
		desc = "Client Fuzz: RefID Malicious Pattern (AAAA)"
	case 8:
		packet.OrigTimeSec = packet.XmitTimeSec + 999999
		desc = "Client Fuzz: Desynced Origin Timestamp"
	case 9:
		packet.SetTransmitTime(time.Time{})
		desc = "Client Fuzz: Zero Timestamp"
	}

	return packet, desc
}
