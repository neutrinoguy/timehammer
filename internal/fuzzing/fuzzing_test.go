package fuzzing

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/pkg/ntpcore"
)

func TestSaveAndLoadCrashReport(t *testing.T) {
	config.EnsureDataDir()

	pkt := ntpcore.NewPacket()
	pkt.Version = 4
	pkt.Mode = ntpcore.ModeServer

	report, err := SaveCrashReport("test_crash", "127.0.0.1:123", "Fuzz: Max Timestamps", pkt.Bytes(), pkt, 10*time.Second)
	if err != nil {
		t.Fatalf("SaveCrashReport failed: %v", err)
	}

	if report.ID == "" {
		t.Fatalf("Expected valid crash report ID")
	}

	loaded, err := LoadCrashReport(report.ID)
	if err != nil {
		t.Fatalf("LoadCrashReport failed: %v", err)
	}

	if loaded.TargetAddress != "127.0.0.1:123" {
		t.Errorf("Expected target 127.0.0.1:123, got %s", loaded.TargetAddress)
	}

	dataDir, _ := config.GetDataDir()
	os.Remove(filepath.Join(dataDir, "crashes", report.ID+".json"))
}
