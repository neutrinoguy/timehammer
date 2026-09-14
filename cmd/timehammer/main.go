// TimeHammer - NTP Security Testing Tool
// A standalone, cross-platform NTP server for security testing of IoT/Embedded devices
//
// Copyright (c) 2026 TimeHammer Contributors
// Licensed under the MIT License
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/fuzzing"
	"github.com/neutrinoguy/timehammer/internal/logger"
	"github.com/neutrinoguy/timehammer/internal/server"
	"github.com/neutrinoguy/timehammer/internal/tui"
)

const (
	AppName    = "TimeHammer"
	AppVersion = "1.0.4"
	AppDesc    = "NTP Security Testing Tool for IoT/Embedded Devices"
)

var (
	showVersion = flag.Bool("version", false, "Show version information")
	showHelp    = flag.Bool("help", false, "Show help information")
	headless    = flag.Bool("headless", false, "Run in headless mode (no TUI)")
	configPath  = flag.String("config", "", "Path to configuration file")
	fuzzServer  = flag.Bool("fuzz-server", false, "Run NTP Server Fuzzing mode (TimeHammer as Client)")
	targetAddr  = flag.String("target", "", "Target NTP Server address for fuzzing/replay (host:port)")
	replayCrash = flag.String("replay", "", "Replay payload from specified crash JSON file or ID")
	listCrashes = flag.Bool("list-crashes", false, "List recorded crash artifacts")
)

func main() {
	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Printf("%s v%s\n%s\n", AppName, AppVersion, AppDesc)
		os.Exit(0)
	}

	// Handle help flag
	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	// Print banner
	printBanner()

	// Ensure data directory exists
	dataDir, err := config.EnsureDataDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("📁 Data directory: %s\n", dataDir)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("⚙️  Configuration loaded")

	// Initialize logger
	log := logger.GetLogger()
	if err := log.Initialize(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.Info("STARTUP", fmt.Sprintf("%s v%s starting...", AppName, AppVersion))
	log.Infof("STARTUP", "OS: %s", config.GetOSInfo())

	// Handle listing crashes flag
	if *listCrashes {
		handleListCrashes()
		os.Exit(0)
	}

	// Handle replay flag
	if *replayCrash != "" {
		handleReplayCrash(*replayCrash, *targetAddr)
		os.Exit(0)
	}

	// Create server
	srv := server.NewServer(cfg)

	// Print warning
	printWarning()

	if *fuzzServer {
		handleRunServerFuzzer(cfg, *targetAddr)
	} else if *headless {
		// Headless mode
		runHeadless(srv, cfg, log)
	} else {
		// TUI mode
		runTUI(srv, cfg)
	}
}

func runTUI(srv *server.Server, cfg *config.Config) {
	app := tui.NewApp(cfg, srv)

	fmt.Println("\n🚀 Launching TUI...")
	fmt.Println("   Press F10 to start server, ? for help, F12 to quit")

	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}

	// Save config on exit
	cfg.Save()
	fmt.Println("\n👋 Goodbye!")
}

func runHeadless(srv *server.Server, cfg *config.Config, log *logger.Logger) {
	fmt.Println("\n🤖 Running in headless mode...")

	// Start server
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Server listening on %s\n", srv.GetListenAddress())

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Press Ctrl+C to stop...")

	<-sigChan

	fmt.Println("\n🛑 Shutting down...")
	srv.Stop()
	cfg.Save()
	fmt.Println("👋 Goodbye!")
}

func handleListCrashes() {
	crashes, err := fuzzing.ListCrashReports()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing crash reports: %v\n", err)
		return
	}

	if len(crashes) == 0 {
		fmt.Println("No crash reports found in .timehammer/crashes/")
		return
	}

	fmt.Printf("🔍 Found %d crash report(s):\n\n", len(crashes))
	for i, c := range crashes {
		fmt.Printf("%d) ID: %s | Type: %s | Target: %s\n", i+1, c.ID, c.Type, c.TargetAddress)
		fmt.Printf("   Timestamp: %s | Mutation: %s\n", c.Timestamp.Format(time.RFC3339), c.FuzzMutation)
		fmt.Printf("   Payload Hex: %s\n\n", c.PacketHex)
	}
}

func handleReplayCrash(crashIDOrPath, targetOverride string) {
	report, err := fuzzing.LoadCrashReport(crashIDOrPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading crash report: %v\n", err)
		os.Exit(1)
	}

	target := report.TargetAddress
	if targetOverride != "" {
		target = targetOverride
	}

	if target == "" {
		fmt.Fprintf(os.Stderr, "Error: No target address specified in crash report or CLI arguments.\n")
		os.Exit(1)
	}

	rawBytes, err := hex.DecodeString(report.PacketHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding payload hex: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("⚡ Replaying crash payload [%s] (%s) to target %s...\n", report.ID, report.FuzzMutation, target)
	resp, err := fuzzing.ReplayPayload(target, rawBytes, 3*time.Second)
	if err != nil {
		fmt.Printf("❌ Target did not respond or timed out: %v\n", err)
		fmt.Println("   (Target remote NTP server appears to be CRASHED / UNRESPONSIVE)")
	} else {
		fmt.Printf("✅ Target responded with %d bytes!\n", len(resp))
	}
}

func handleRunServerFuzzer(cfg *config.Config, targetOverride string) {
	if targetOverride != "" {
		cfg.Security.ServerFuzzing.Target = targetOverride
	}

	if cfg.Security.ServerFuzzing.Target == "" {
		fmt.Fprintf(os.Stderr, "Error: Target address is required for Server Fuzzing (use --target host:port)\n")
		os.Exit(1)
	}

	fuzzer := fuzzing.NewServerFuzzer(cfg)
	if err := fuzzer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server fuzzer: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 NTP Server Fuzzer running against %s...\n", cfg.Security.ServerFuzzing.Target)
	fmt.Println("Press Ctrl+C to stop...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println("\n🛑 Stopping Server Fuzzer...")
	fuzzer.Stop()
}

func printBanner() {
	banner := `
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ████████╗██╗███╗   ███╗███████╗                             ║
║   ╚══██╔══╝██║████╗ ████║██╔════╝                             ║
║      ██║   ██║██╔████╔██║█████╗                               ║
║      ██║   ██║██║╚██╔╝██║██╔══╝                               ║
║      ██║   ██║██║ ╚═╝ ██║███████╗                             ║
║      ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝                             ║
║   ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗       ║
║   ██║  ██║██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗      ║
║   ███████║███████║██╔████╔██║██╔████╔██║█████╗  ██████╔╝      ║
║   ██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██╔══██╗      ║
║   ██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║  ██║      ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝      ║
║                                                                ║
║              NTP Security Testing Tool v1.0.4                  ║
║         For IoT, IIoT, and Embedded Device Testing            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func printWarning() {
	warning := `
┌────────────────────────────────────────────────────────────────┐
│  ⚠️  WARNING: SECURITY TESTING TOOL                           │
│                                                                │
│  This tool is designed for SECURITY TESTING purposes only.    │
│  It can manipulate NTP responses to test how devices handle   │
│  various time-based attacks.                                  │
│                                                                │
│  ❌ DO NOT use on production systems                          │
│  ❌ DO NOT use without authorization                          │
│  ❌ DO NOT use on networks you don't own/control              │
│                                                                │
│  ✅ Use in isolated test environments only                    │
│  ✅ Get proper authorization before testing                   │
│  ✅ Document all testing activities                           │
│                                                                │
│  The authors are not responsible for misuse of this tool.     │
└────────────────────────────────────────────────────────────────┘
`
	fmt.Println(warning)
}

func printHelp() {
	fmt.Printf(`%s v%s - %s

USAGE:
    timehammer [OPTIONS]

OPTIONS:
    --help                 Show this help message
    --version              Show version information
    --headless             Run in headless mode (no TUI)
    --config PATH          Use specific configuration file
    --fuzz-server          Run NTP Server Fuzzing mode (TimeHammer as Client)
    --target HOST:PORT     Target NTP Server address for fuzzing or payload replay
    --replay CRASH_FILE    Replay fuzzed payload from crash JSON file or ID
    --list-crashes         List all recorded fuzzing crash artifacts

KEYBOARD SHORTCUTS (TUI Mode):
    F1                     Dashboard
    F2                     View Logs
    F3                     Edit Configuration
    F4                     Attack Mode / Security Testing
    F5                     Session Management
    F6                     Server Fuzzing Mode
    F10                    Start/Stop Server
    F12 / Esc              Quit
    Ctrl+S                 Save Configuration
    Ctrl+E                 Export Logs (JSON & CSV)
    Ctrl+R                 Toggle Session Recording
    Ctrl+U                 Force Upstream Sync
    ?                      Show Help

SECURITY ATTACKS:
    - Time Spoofing: Send fake time to clients
    - Gradual Drift: Slowly drift time to evade detection
    - Kiss-of-Death: Send KoD packets (CVE-2015-7704/7705)
    - Stratum Attack: Claim higher authority
    - Leap Second: Inject leap second flags
    - Rollover: Test Y2K38 and NTP era bugs
    - Clock Step: Sudden large time jumps
    - Client Fuzzing: Rate-monitored mutation with crash logging & replay
    - Server Fuzzing: Target server mutation with health probes & crash recording

FILES:
    ./.timehammer/config.yaml     Configuration file
    ./.timehammer/timehammer.log  Log file
    ./.timehammer/sessions/       Session recordings
    ./.timehammer/crashes/        Fuzzing crash reports
    ./.timehammer/exports/        Exported logs (JSON/CSV)

EXAMPLES:
    # Run with TUI (default)
    timehammer

    # Run in headless mode
    timehammer --headless

    # Fuzz a remote NTP Server (TimeHammer as Client)
    timehammer --fuzz-server --target 192.168.1.50:123

    # Replay a recorded crash against target
    timehammer --replay crash_client_crash_1773469324.json --target 192.168.1.50:123

    # List recorded crash reports
    timehammer --list-crashes

For more information, visit: https://github.com/neutrinoguy/timehammer
`, AppName, AppVersion, AppDesc)
}
