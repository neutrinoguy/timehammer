// Package fuzzing handles client/server NTP fuzzing, crash logging, and replay
package fuzzing

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/pkg/ntpcore"
)

// CrashReport represents a recorded fuzzing crash artifact
type CrashReport struct {
	ID             string             `json:"id"`
	Type           string             `json:"type"` // "client_crash" or "server_crash"
	Timestamp      time.Time          `json:"timestamp"`
	TargetAddress  string             `json:"target_address"`
	FuzzMutation   string             `json:"fuzz_mutation"`
	InactivitySecs float64            `json:"inactivity_secs,omitempty"`
	PacketHex      string             `json:"packet_hex"`
	ParsedPacket   *sessionPacketInfo `json:"parsed_packet,omitempty"`
	PythonBoiler   string             `json:"python_boilerplate"`
}

type sessionPacketInfo struct {
	LeapIndicator uint8  `json:"leap_indicator"`
	Version       uint8  `json:"version"`
	Mode          string `json:"mode"`
	Stratum       uint8  `json:"stratum"`
	Poll          int8   `json:"poll"`
	Precision     int8   `json:"precision"`
	ReferenceID   string `json:"reference_id"`
}

// SaveCrashReport serializes and saves a crash report with Python boilerplate
func SaveCrashReport(crashType, targetAddr, mutation string, rawPacket []byte, parsed *ntpcore.NTPPacket, inactivity time.Duration) (*CrashReport, error) {
	dataDir, err := config.GetDataDir()
	if err != nil {
		return nil, err
	}

	crashesDir := filepath.Join(dataDir, "crashes")
	if err := os.MkdirAll(crashesDir, 0755); err != nil {
		return nil, err
	}

	timestamp := time.Now()
	crashID := fmt.Sprintf("crash_%s_%d", crashType, timestamp.UnixNano())
	hexData := hex.EncodeToString(rawPacket)

	report := &CrashReport{
		ID:             crashID,
		Type:           crashType,
		Timestamp:      timestamp,
		TargetAddress:  targetAddr,
		FuzzMutation:   mutation,
		InactivitySecs: inactivity.Seconds(),
		PacketHex:      hexData,
		PythonBoiler:   generatePythonBoilerplate(targetAddr, hexData),
	}

	if parsed != nil {
		report.ParsedPacket = &sessionPacketInfo{
			LeapIndicator: parsed.LeapIndicator,
			Version:       parsed.Version,
			Mode:          parsed.GetModeString(),
			Stratum:       parsed.Stratum,
			Poll:          parsed.Poll,
			Precision:     parsed.Precision,
			ReferenceID:   fmt.Sprintf("0x%08X", parsed.ReferenceID),
		}
	}

	filePath := filepath.Join(crashesDir, crashID+".json")
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(filePath, bytes, 0644); err != nil {
		return nil, err
	}

	return report, nil
}

// ReplayPayload sends the recorded payload to the specified target address
func ReplayPayload(targetAddr string, rawBytes []byte, timeout time.Duration) ([]byte, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target UDP: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	_, err = conn.Write(rawBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send replay payload: %w", err)
	}

	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, fmt.Errorf("no response received (target may be unresponsive/crashed): %w", err)
	}

	return buffer[:n], nil
}

// LoadCrashReport loads a crash file from disk
func LoadCrashReport(crashIDOrPath string) (*CrashReport, error) {
	path := crashIDOrPath
	if !filepath.IsAbs(path) && filepath.Ext(path) == "" {
		dataDir, err := config.GetDataDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dataDir, "crashes", crashIDOrPath+".json")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read crash file: %w", err)
	}

	var report CrashReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("invalid crash json structure: %w", err)
	}

	return &report, nil
}

// ListCrashReports returns all recorded crashes
func ListCrashReports() ([]CrashReport, error) {
	dataDir, err := config.GetDataDir()
	if err != nil {
		return nil, err
	}

	crashesDir := filepath.Join(dataDir, "crashes")
	entries, err := os.ReadDir(crashesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []CrashReport{}, nil
		}
		return nil, err
	}

	var crashes []CrashReport
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(crashesDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var report CrashReport
		if err := json.Unmarshal(data, &report); err == nil {
			crashes = append(crashes, report)
		}
	}

	return crashes, nil
}

func generatePythonBoilerplate(targetAddr, hexData string) string {
	host := "127.0.0.1"
	port := 123
	if targetAddr != "" {
		if h, p, err := net.SplitHostPort(targetAddr); err == nil {
			host = h
			fmt.Sscanf(p, "%d", &port)
		}
	}

	return fmt.Sprintf(`# TimeHammer Fuzzing Crash Replay Script
import socket
import sys

TARGET_HOST = "%s"
TARGET_PORT = %d
PAYLOAD_HEX = "%s"

def main():
    payload = bytes.fromhex(PAYLOAD_HEX)
    print(f"[*] Replaying {len(payload)} bytes payload to {TARGET_HOST}:{TARGET_PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    try:
        sock.sendto(payload, (TARGET_HOST, TARGET_PORT))
        response, addr = sock.recvfrom(1024)
        print(f"[+] Received response from {addr}: {len(response)} bytes")
    except socket.timeout:
        print("[-] Timeout: Remote target did not respond (Target crashed or unresponsive).")
    except Exception as e:
        print(f"[-] Error during replay: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
`, host, port, hexData)
}
