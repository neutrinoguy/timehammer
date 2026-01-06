// TimeHammer - NTP Security Testing Tool
// A standalone, cross-platform NTP server for security testing of IoT/Embedded devices
//
// Copyright (c) 2026 TimeHammer Contributors
// Licensed under the MIT License
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/logger"
	"github.com/neutrinoguy/timehammer/internal/server"
	"github.com/neutrinoguy/timehammer/internal/tui"
)

const (
	AppName    = "TimeHammer"
	AppVersion = "1.0.0"
	AppDesc    = "NTP Security Testing Tool for IoT/Embedded Devices"
)

var (
	showVersion = flag.Bool("version", false, "Show version information")
	showHelp    = flag.Bool("help", false, "Show help information")
	headless    = flag.Bool("headless", false, "Run in headless mode (no TUI)")
	configPath  = flag.String("config", "", "Path to configuration file")
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

	// Create server
	srv := server.NewServer(cfg)

	// Print warning
	printWarning()

	if *headless {
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
║              NTP Security Testing Tool v1.0.0                  ║
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
    --help          Show this help message
    --version       Show version information
    --headless      Run in headless mode (no TUI)
    --config PATH   Use specific configuration file

KEYBOARD SHORTCUTS (TUI Mode):
    F1              Dashboard
    F2              View Logs
    F3              Edit Configuration
    F4              Attack Mode / Security Testing
    F5              Session Management
    F10             Start/Stop Server
    F12 / Esc       Quit
    Ctrl+S          Save Configuration
    Ctrl+E          Export Logs (JSON & CSV)
    Ctrl+R          Toggle Session Recording
    Ctrl+U          Force Upstream Sync
    ?               Show Help

SECURITY ATTACKS:
    - Time Spoofing: Send fake time to clients
    - Gradual Drift: Slowly drift time to evade detection
    - Kiss-of-Death: Send KoD packets (CVE-2015-7704/7705)
    - Stratum Attack: Claim higher authority
    - Leap Second: Inject leap second flags
    - Rollover: Test Y2K38 and NTP era bugs
    - Clock Step: Sudden large time jumps

FILES:
    ./..timehammer/config.yaml     Configuration file
    ./..timehammer/timehammer.log  Log file
    ./..timehammer/sessions/       Session recordings
    ./..timehammer/exports/        Exported logs (JSON/CSV)

EXAMPLES:
    # Run with TUI (default)
    timehammer

    # Run in headless mode
    timehammer --headless

    # Use specific config
    timehammer --config /path/to/config.yaml

For more information, visit: https://github.com/neutrinoguy/timehammer
`, AppName, AppVersion, AppDesc)
}
