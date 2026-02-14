// Package tui provides the terminal user interface
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/neutrinoguy/timehammer/internal/attacks"
	"github.com/neutrinoguy/timehammer/internal/config"
	"github.com/neutrinoguy/timehammer/internal/logger"
	"github.com/neutrinoguy/timehammer/internal/server"
	"github.com/neutrinoguy/timehammer/internal/session"
)

// Colors
var (
	ColorPrimary    = tcell.ColorDodgerBlue
	ColorSecondary  = tcell.ColorLightGray
	ColorSuccess    = tcell.ColorLimeGreen
	ColorWarning    = tcell.ColorOrange
	ColorDanger     = tcell.ColorRed
	ColorAccent     = tcell.ColorMediumPurple
	ColorBackground = tcell.ColorBlack
)

// App represents the TUI application
type App struct {
	app      *tview.Application
	pages    *tview.Pages
	cfg      *config.Config
	server   *server.Server
	log      *logger.Logger
	recorder *session.SessionRecorder

	// UI Components
	mainFlex      *tview.Flex
	header        *tview.TextView
	footer        *tview.TextView
	statusBar     *tview.TextView
	logView       *tview.TextView
	dashboardView *tview.Flex
	configEditor  *tview.TextArea
	attackPanel   *tview.Flex
	helpModal     *tview.Modal
	sessionPanel  *tview.Flex

	// State
	currentPage string
	logChan     chan logger.LogEntry
}

// NewApp creates a new TUI application
func NewApp(cfg *config.Config, srv *server.Server) *App {
	a := &App{
		app:      tview.NewApplication(),
		pages:    tview.NewPages(),
		cfg:      cfg,
		server:   srv,
		log:      logger.GetLogger(),
		recorder: session.GetRecorder(),
	}

	a.setupUI()
	return a
}

// setupUI initializes all UI components
func (a *App) setupUI() {
	// Create header
	a.header = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	a.updateHeader()
	a.header.SetBackgroundColor(ColorPrimary)
	a.header.SetTextColor(tcell.ColorWhite)

	// Create footer with keybindings
	a.footer = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	a.footer.SetText(" [yellow]F1[white] Dashboard │ [yellow]F2[white] Logs │ [yellow]F3[white] Config │ [yellow]F4[white] Attacks │ [yellow]F5[white] Sessions │ [yellow]F10[white] Start/Stop │ [yellow]F12[white] Quit │ [yellow]?[white] Help ")
	a.footer.SetBackgroundColor(tcell.ColorDarkSlateGray)

	// Create status bar
	a.statusBar = tview.NewTextView().
		SetDynamicColors(true)
	a.updateStatusBar()

	// Create main content views
	a.createDashboardView()
	a.createLogView()
	a.createConfigEditor()
	a.createAttackPanel()
	a.createSessionPanel()
	a.createHelpModal()

	// Add pages
	a.pages.AddPage("dashboard", a.dashboardView, true, true)
	a.pages.AddPage("logs", a.logView, true, false)
	a.pages.AddPage("config", a.configEditor, true, false)
	a.pages.AddPage("attacks", a.attackPanel, true, false)
	a.pages.AddPage("sessions", a.sessionPanel, true, false)

	// Create main layout
	a.mainFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.header, 3, 0, false).
		AddItem(a.pages, 0, 1, true).
		AddItem(a.statusBar, 1, 0, false).
		AddItem(a.footer, 1, 0, false)

	// Set up input capture for global keybindings
	a.app.SetInputCapture(a.handleGlobalKeys)

	a.app.SetRoot(a.mainFlex, true)
	a.currentPage = "dashboard"

	// Subscribe to log updates
	a.logChan = a.log.Subscribe()
	go a.handleLogUpdates()
}

// createDashboardView creates the main dashboard
func (a *App) createDashboardView() {
	// Server status panel
	serverStatus := tview.NewTextView().SetDynamicColors(true)
	serverStatus.SetBorder(true)
	serverStatus.SetTitle(" 🔌 Server Status ")
	serverStatus.SetBorderColor(ColorPrimary)

	// Upstream status panel
	upstreamStatus := tview.NewTextView().SetDynamicColors(true)
	upstreamStatus.SetBorder(true)
	upstreamStatus.SetTitle(" ⬆️ Upstream Sync ")
	upstreamStatus.SetBorderColor(ColorAccent)

	// Statistics panel
	statsPanel := tview.NewTextView().SetDynamicColors(true)
	statsPanel.SetBorder(true)
	statsPanel.SetTitle(" 📊 Statistics ")
	statsPanel.SetBorderColor(ColorSuccess)

	// Active clients panel
	clientsPanel := tview.NewTextView().SetDynamicColors(true)
	clientsPanel.SetBorder(true)
	clientsPanel.SetTitle(" 👥 Active Clients ")
	clientsPanel.SetBorderColor(ColorSecondary)

	// Attack status panel
	attackStatus := tview.NewTextView().SetDynamicColors(true)
	attackStatus.SetBorder(true)
	attackStatus.SetTitle(" ⚔️ Security Mode ")
	attackStatus.SetBorderColor(ColorDanger)

	// Quick log panel
	quickLog := tview.NewTextView().SetDynamicColors(true)
	quickLog.SetBorder(true)
	quickLog.SetTitle(" 📜 Recent Logs ")
	quickLog.SetBorderColor(ColorWarning)
	quickLog.SetScrollable(true)

	// Layout
	topRow := tview.NewFlex().
		AddItem(serverStatus, 0, 1, false).
		AddItem(upstreamStatus, 0, 1, false).
		AddItem(statsPanel, 0, 1, false)

	middleRow := tview.NewFlex().
		AddItem(clientsPanel, 0, 1, false).
		AddItem(attackStatus, 0, 1, false)

	a.dashboardView = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topRow, 11, 0, false).
		AddItem(middleRow, 8, 0, false).
		AddItem(quickLog, 0, 1, false)

	// Update dashboard periodically
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			a.app.QueueUpdateDraw(func() {
				a.updateDashboardPanel(serverStatus, upstreamStatus, statsPanel, clientsPanel, attackStatus, quickLog)
			})
		}
	}()
}

// updateDashboardPanel updates all dashboard panels
func (a *App) updateDashboardPanel(serverStatus, upstreamStatus, statsPanel, clientsPanel, attackStatus, quickLog *tview.TextView) {
	// Server status
	if a.server.IsRunning() {
		serverStatus.SetText(fmt.Sprintf(`
  [green]● RUNNING[white]
  
  Listen: [cyan]%s[white]
  Port: [cyan]%d[white]
  Interface: [cyan]%s[white]
  Timezone: [cyan]%s[white]
  Max Clients: [cyan]%d[white]`,
			a.server.GetListenAddress(),
			a.cfg.Server.Port,
			orDefault(a.cfg.Server.Interface, "all"),
			orDefault(a.cfg.Server.Timezone, "UTC"),
			a.cfg.Server.MaxClients))
	} else {
		serverStatus.SetText(fmt.Sprintf(`
  [red]● STOPPED[white]
  
  Port: [gray]%d[white]
  Interface: [gray]%s[white]
  Timezone: [gray]%s[white]
  
  Press [yellow]F10[white] to start server`,
			a.cfg.Server.Port,
			orDefault(a.cfg.Server.Interface, "all"),
			orDefault(a.cfg.Server.Timezone, "UTC")))
	}

	// Upstream status
	sync := a.server.GetUpstreamStatus()
	if sync.Synchronized {
		upstreamStatus.SetText(fmt.Sprintf(`
  [green]● SYNCHRONIZED[white]
  
  Server: [cyan]%s[white]
  Stratum: [cyan]%d[white]
  Offset: [cyan]%v[white]
  RTT: [cyan]%v[white]
  Last Sync: [cyan]%s[white]`,
			sync.ActiveServer,
			sync.Stratum,
			sync.Offset,
			sync.RTT,
			sync.LastSync.Format("15:04:05")))
	} else {
		errMsg := sync.LastError
		if errMsg == "" {
			errMsg = "Not yet synced"
		}
		upstreamStatus.SetText(fmt.Sprintf(`
  [yellow]● UNSYNCHRONIZED[white]
  
  Status: [red]%s[white]
  
  Press [yellow]Ctrl+U[white] to force sync`, errMsg))
	}

	// Statistics
	stats := a.server.GetStats()
	statsPanel.SetText(fmt.Sprintf(`
  Uptime: [cyan]%s[white]
  
  Requests: [green]%d[white]
  Responses: [green]%d[white]
  Errors: [red]%d[white]
  Attacks: [yellow]%d[white]`,
		formatDuration(stats.Uptime),
		stats.TotalRequests,
		stats.TotalResponses,
		stats.ErrorCount,
		stats.AttacksExecuted))

	// Active clients
	clients := a.server.GetActiveClients()
	if len(clients) == 0 {
		clientsPanel.SetText("\n  [gray]No active clients[white]")
	} else {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("\n  [cyan]%d[white] client(s):\n\n", len(clients)))
		maxShow := 8
		for i, client := range clients {
			if i >= maxShow {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(clients)-maxShow))
				break
			}
			ago := time.Since(client.LastSeen)
			sb.WriteString(fmt.Sprintf("  • %s [gray](%s ago)[white]\n", client.Address, formatDuration(ago)))
		}
		clientsPanel.SetText(sb.String())
	}

	// Attack status
	if a.cfg.Security.Enabled {
		activeAttack := a.cfg.Security.ActiveAttack
		if activeAttack == "" {
			activeAttack = "None"
		}
		attackStatus.SetText(fmt.Sprintf(`
  [red]⚠️ SECURITY MODE ACTIVE[white]
  
  Attack: [yellow]%s[white]
  
  [red]WARNING: All responses are modified![white]
  
  Press [yellow]F4[white] for attack options`, activeAttack))
		attackStatus.SetBorderColor(ColorDanger)
	} else {
		attackStatus.SetText(`
  [green]● NORMAL MODE[white]
  
  Security testing mode is [green]disabled[white]
  
  Press [yellow]F4[white] to enable attacks`)
		attackStatus.SetBorderColor(ColorSuccess)
	}

	// Quick log
	entries := a.log.GetEntries(15)
	var logSb strings.Builder
	for _, entry := range entries {
		color := "white"
		switch entry.Level {
		case logger.LevelDebug:
			color = "gray"
		case logger.LevelInfo:
			color = "green"
		case logger.LevelWarn:
			color = "yellow"
		case logger.LevelError:
			color = "red"
		}
		logSb.WriteString(fmt.Sprintf("[%s]%s [%s] %s[white]\n",
			color, entry.Timestamp.Format("15:04:05"), entry.Category, truncate(entry.Message, 60)))
	}
	quickLog.SetText(logSb.String())
	quickLog.ScrollToEnd()
}

// createLogView creates the log viewer
func (a *App) createLogView() {
	a.logView = tview.NewTextView().SetDynamicColors(true)
	a.logView.SetScrollable(true)
	a.logView.SetBorder(true)
	a.logView.SetTitle(" 📜 Logs [Ctrl+C to clear, Ctrl+E to export] ")
	a.logView.SetBorderColor(ColorPrimary)
}

// createConfigEditor creates the configuration editor
func (a *App) createConfigEditor() {
	a.configEditor = tview.NewTextArea().
		SetPlaceholder("Loading configuration...")
	a.configEditor.SetBorder(true)
	a.configEditor.SetTitle(" ⚙️ Configuration [Ctrl+S to save] ")
	a.configEditor.SetBorderColor(ColorWarning)

	// Load current config
	yaml, _ := a.cfg.GetYAML()
	a.configEditor.SetText(yaml, true)
}

// createAttackPanel creates the attack selection panel
func (a *App) createAttackPanel() {
	// Attack list
	attackList := tview.NewList().
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(ColorPrimary)
	attackList.SetBorder(true)
	attackList.SetTitle(" ⚔️ Available Attacks [Tab: switch] ")

	availableAttacks := attacks.GetAvailableAttacks()
	for _, attack := range availableAttacks {
		info := attack // capture
		attackList.AddItem(info.Name, info.Description, 0, func() {
			a.selectAttack(info)
		})
	}

	// Add disable option
	attackList.AddItem("[Disable All Attacks]", "Return to normal operation", 0, func() {
		a.server.GetAttackEngine().DisableAllAttacks()
		a.cfg.Security.Enabled = false
		a.log.Info("ATTACK", "All attacks disabled")
	})

	// Attack details
	attackDetails := tview.NewTextView().SetDynamicColors(true)
	attackDetails.SetBorder(true)
	attackDetails.SetTitle(" 📋 Attack Details ")
	attackDetails.SetBorderColor(ColorSecondary)

	attackDetails.SetText(`
  Select an attack from the list to see details.
  
  [yellow]Available Attacks:[white]
  
  • Time Spoofing - Send fake time to clients
  • Gradual Drift - Slowly drift time undetected
  • Kiss-of-Death - Disable client synchronization
  • Stratum Attack - Claim higher authority
  • Leap Second - Inject leap second flags
  • Rollover - Test Y2K38 and NTP era bugs
  • Clock Step - Sudden large time jumps
  
  [yellow]Press Tab[white] to switch between Attacks and Presets
  
  [red]⚠️ Use only in controlled test environments![white]`)

	// Preset list
	presetList := tview.NewList().
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(ColorAccent)
	presetList.SetBorder(true)
	presetList.SetTitle(" 🎯 Attack Presets [Tab: switch] ")

	for _, preset := range a.cfg.AttackPresets {
		p := preset // capture
		presetList.AddItem(p.Name, p.Description, 0, func() {
			a.server.GetAttackEngine().ApplyPreset(p)
			a.cfg.Security.Enabled = true
			a.cfg.Security.ActiveAttack = p.Attack
			a.log.Infof("ATTACK", "Applied preset: %s", p.Name)
		})
	}

	// Handle Tab key to switch focus between lists
	attackList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTab {
			a.app.SetFocus(presetList)
			return nil
		}
		return event
	})

	presetList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
			a.app.SetFocus(attackList)
			return nil
		}
		return event
	})

	// Layout
	leftPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(attackList, 0, 1, true).
		AddItem(presetList, 10, 0, false)

	a.attackPanel = tview.NewFlex().
		AddItem(leftPane, 40, 0, true).
		AddItem(attackDetails, 0, 1, false)
}

// createSessionPanel creates the session management panel
func (a *App) createSessionPanel() {
	// Recording status
	recordingStatus := tview.NewTextView().SetDynamicColors(true)
	recordingStatus.SetBorder(true)
	recordingStatus.SetTitle(" 🎬 Recording ")
	recordingStatus.SetBorderColor(ColorDanger)

	// Session list
	sessionList := tview.NewList().
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(ColorPrimary)
	sessionList.SetBorder(true)
	sessionList.SetTitle(" 📁 Saved Sessions ")

	// Session details
	sessionDetails := tview.NewTextView().SetDynamicColors(true)
	sessionDetails.SetBorder(true)
	sessionDetails.SetTitle(" 📋 Session Details ")
	sessionDetails.SetBorderColor(ColorSecondary)

	// Update session info
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			a.app.QueueUpdateDraw(func() {
				if a.recorder.IsRecording() {
					sess := a.recorder.GetCurrentSession()
					if sess != nil {
						duration := time.Since(sess.StartTime)
						recordingStatus.SetText(fmt.Sprintf(`
  [red]● RECORDING[white]
  
  Session: [cyan]%s[white]
  Duration: [cyan]%s[white]
  Events: [cyan]%d[white]
  
  Press [yellow]Ctrl+R[white] to stop`, sess.ID, formatDuration(duration), sess.EventCount))
					}
				} else {
					recordingStatus.SetText(`
  [gray]○ NOT RECORDING[white]
  
  Press [yellow]Ctrl+R[white] to start recording`)
				}
			})
		}
	}()

	// Load sessions
	a.refreshSessionList(sessionList, sessionDetails)

	// Layout
	leftPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(recordingStatus, 8, 0, false).
		AddItem(sessionList, 0, 1, true)

	a.sessionPanel = tview.NewFlex().
		AddItem(leftPane, 40, 0, true).
		AddItem(sessionDetails, 0, 1, false)
}

// refreshSessionList refreshes the session list
func (a *App) refreshSessionList(sessionList *tview.List, sessionDetails *tview.TextView) {
	sessionList.Clear()

	sessions, err := session.ListSessions()
	if err != nil {
		sessionDetails.SetText(fmt.Sprintf("[red]Error loading sessions: %v[white]", err))
		return
	}

	if len(sessions) == 0 {
		sessionDetails.SetText("\n  [gray]No saved sessions[white]\n\n  Start a recording with [yellow]Ctrl+R[white]")
		return
	}

	for _, sess := range sessions {
		s := sess // capture
		sessionList.AddItem(s.ID, s.StartTime.Format("2006-01-02 15:04:05"), 0, func() {
			sessionDetails.SetText(fmt.Sprintf(`
  [cyan]Session ID:[white] %s
  [cyan]Description:[white] %s
  [cyan]Start:[white] %s
  [cyan]End:[white] %s
  [cyan]Duration:[white] %s
  
  [yellow]Statistics:[white]
  • Requests: %d
  • Responses: %d
  • Unique Clients: %d
  • Upstream Queries: %d
  • Attacks Executed: %d
  • Avg Response Time: %v`,
				s.ID,
				orDefault(s.Description, "None"),
				s.StartTime.Format(time.RFC3339),
				s.EndTime.Format(time.RFC3339),
				s.EndTime.Sub(s.StartTime).String(),
				s.Stats.TotalRequests,
				s.Stats.TotalResponses,
				s.Stats.UniqueClients,
				s.Stats.UpstreamQueries,
				s.Stats.AttacksExecuted,
				s.Stats.AvgResponseTime))
		})
	}
}

// createHelpModal creates the help modal
func (a *App) createHelpModal() {
	helpText := `TimeHammer - NTP Security Testing Tool

⌨️  KEYBOARD SHORTCUTS:

  F1         - Dashboard
  F2         - View Logs
  F3         - Edit Configuration
  F4         - Attack Mode
  F5         - Session Management
  F10        - Start/Stop Server
  F12 / Esc  - Quit

  Ctrl+S     - Save Configuration
  Ctrl+E     - Export Logs
  Ctrl+C     - Clear Logs (in log view)
  Ctrl+R     - Toggle Recording
  Ctrl+U     - Force Upstream Sync

⚠️  WARNING: This tool is for security testing only!
    Never use on production systems.

Press any key to close this help.`

	a.helpModal = tview.NewModal().
		SetText(helpText).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			a.pages.HidePage("help")
		})
}

// selectAttack handles attack selection
func (a *App) selectAttack(info attacks.AttackInfo) {
	a.cfg.Security.Enabled = true
	a.cfg.Security.ActiveAttack = string(info.Type)

	// Enable the specific attack
	switch info.Type {
	case attacks.AttackTimeSpoofing:
		a.cfg.Security.TimeSpoofing.Enabled = true
	case attacks.AttackTimeDrift:
		a.cfg.Security.TimeDrift.Enabled = true
		a.server.GetAttackEngine().ResetDriftState()
	case attacks.AttackKissOfDeath:
		a.cfg.Security.KissOfDeath.Enabled = true
	case attacks.AttackStratumLie:
		a.cfg.Security.StratumAttack.Enabled = true
	case attacks.AttackLeapSecond:
		a.cfg.Security.LeapSecond.Enabled = true
	case attacks.AttackRollover:
		a.cfg.Security.Rollover.Enabled = true
	case attacks.AttackClockStep:
		a.cfg.Security.ClockStep.Enabled = true
	case attacks.AttackFuzzing:
		a.cfg.Security.Fuzzing.Enabled = true
	}

	a.log.Infof("ATTACK", "Enabled attack: %s - %s", info.Name, info.Description)
}

// handleGlobalKeys handles global keyboard shortcuts
func (a *App) handleGlobalKeys(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyF1:
		a.switchPage("dashboard")
		return nil
	case tcell.KeyF2:
		a.switchPage("logs")
		return nil
	case tcell.KeyF3:
		a.switchPage("config")
		return nil
	case tcell.KeyF4:
		a.switchPage("attacks")
		return nil
	case tcell.KeyF5:
		a.switchPage("sessions")
		return nil
	case tcell.KeyF10:
		a.toggleServer()
		return nil
	case tcell.KeyF12, tcell.KeyEscape:
		a.confirmQuit()
		return nil
	case tcell.KeyCtrlS:
		a.saveConfig()
		return nil
	case tcell.KeyCtrlE:
		a.exportLogs()
		return nil
	case tcell.KeyCtrlR:
		a.toggleRecording()
		return nil
	case tcell.KeyCtrlU:
		a.server.ForceUpstreamSync()
		a.log.Info("SERVER", "Forced upstream sync")
		return nil
	case tcell.KeyCtrlC:
		if a.currentPage == "logs" {
			a.log.ClearEntries()
			a.logView.Clear()
			return nil
		}
	case tcell.KeyRune:
		if event.Rune() == '?' {
			a.showHelp()
			return nil
		}
	}
	return event
}

// switchPage switches to a different page
func (a *App) switchPage(name string) {
	a.pages.SwitchToPage(name)
	a.currentPage = name
	a.updateHeader()

	// Reload config when switching to config page
	if name == "config" {
		a.reloadConfigEditor()
	}
}

// reloadConfigEditor reloads the current config into the editor
func (a *App) reloadConfigEditor() {
	yaml, err := a.cfg.GetYAML()
	if err != nil {
		a.log.Errorf("CONFIG", "Failed to load config: %v", err)
		return
	}
	a.configEditor.SetText(yaml, true)
}

// toggleServer starts or stops the server
func (a *App) toggleServer() {
	if a.server.IsRunning() {
		if err := a.server.Stop(); err != nil {
			a.log.Errorf("SERVER", "Failed to stop: %v", err)
		}
	} else {
		if err := a.server.Start(); err != nil {
			a.log.Errorf("SERVER", "Failed to start: %v", err)
		}
	}
	a.updateStatusBar()
}

// saveConfig saves the configuration
func (a *App) saveConfig() {
	if a.currentPage == "config" {
		yaml := a.configEditor.GetText()
		if err := a.cfg.UpdateFromYAML(yaml); err != nil {
			a.log.Errorf("CONFIG", "Invalid config: %v", err)
			return
		}
	}

	if err := a.cfg.Save(); err != nil {
		a.log.Errorf("CONFIG", "Failed to save: %v", err)
	} else {
		a.log.Info("CONFIG", "Configuration saved")
		a.server.UpdateConfig(a.cfg)
	}
}

// exportLogs exports logs to file
func (a *App) exportLogs() {
	timestamp := time.Now().Format("20060102_150405")

	jsonFile := fmt.Sprintf("logs_%s.json", timestamp)
	if err := a.log.ExportJSON(jsonFile); err != nil {
		a.log.Errorf("EXPORT", "Failed to export JSON: %v", err)
	} else {
		a.log.Infof("EXPORT", "Exported to .timehammer/exports/%s", jsonFile)
	}

	csvFile := fmt.Sprintf("logs_%s.csv", timestamp)
	if err := a.log.ExportCSV(csvFile); err != nil {
		a.log.Errorf("EXPORT", "Failed to export CSV: %v", err)
	} else {
		a.log.Infof("EXPORT", "Exported to .timehammer/exports/%s", csvFile)
	}
}

// toggleRecording toggles session recording
func (a *App) toggleRecording() {
	if a.recorder.IsRecording() {
		sess, err := a.recorder.StopRecording()
		if err != nil {
			a.log.Errorf("SESSION", "Failed to stop recording: %v", err)
		} else {
			a.log.Infof("SESSION", "Recording stopped, saved as %s", sess.ID)
		}
	} else {
		if err := a.recorder.StartRecording("Manual recording"); err != nil {
			a.log.Errorf("SESSION", "Failed to start recording: %v", err)
		} else {
			a.log.Info("SESSION", "Recording started")
		}
	}
}

// showHelp shows the help modal
func (a *App) showHelp() {
	a.pages.AddPage("help", a.helpModal, true, true)
}

// confirmQuit confirms before quitting
func (a *App) confirmQuit() {
	modal := tview.NewModal().
		SetText("Are you sure you want to quit?\n\nThe server will be stopped.").
		AddButtons([]string{"Quit", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Quit" {
				if a.server.IsRunning() {
					a.server.Stop()
				}
				a.app.Stop()
			} else {
				a.pages.RemovePage("confirm_quit")
			}
		})
	a.pages.AddPage("confirm_quit", modal, true, true)
}

// updateHeader updates the header text
func (a *App) updateHeader() {
	pageNames := map[string]string{
		"dashboard": "Dashboard",
		"logs":      "Logs",
		"config":    "Configuration",
		"attacks":   "Security Testing",
		"sessions":  "Sessions",
	}
	pageName := pageNames[a.currentPage]

	a.header.SetText(fmt.Sprintf("\n🔨 TimeHammer - NTP Security Testing Tool │ %s\n", pageName))
}

// updateStatusBar updates the status bar
func (a *App) updateStatusBar() {
	status := "[gray]Server: "
	if a.server.IsRunning() {
		status += "[green]RUNNING[white]"
	} else {
		status += "[red]STOPPED[white]"
	}

	sync := a.server.GetUpstreamStatus()
	status += " │ Upstream: "
	if sync.Synchronized {
		status += fmt.Sprintf("[green]SYNCED[white] (%s)", sync.ActiveServer)
	} else {
		status += "[yellow]UNSYNCED[white]"
	}

	if a.cfg.Security.Enabled {
		status += " │ [red]⚠️ ATTACK MODE ACTIVE[white]"
	}

	if a.recorder.IsRecording() {
		status += " │ [red]🔴 RECORDING[white]"
	}

	a.statusBar.SetText(status)
}

// handleLogUpdates handles log updates from the channel
func (a *App) handleLogUpdates() {
	for entry := range a.logChan {
		a.app.QueueUpdateDraw(func() {
			color := "white"
			switch entry.Level {
			case logger.LevelDebug:
				color = "gray"
			case logger.LevelInfo:
				color = "green"
			case logger.LevelWarn:
				color = "yellow"
			case logger.LevelError:
				color = "red"
			}

			line := fmt.Sprintf("[%s]%s [%s][%s]%s %s[white]\n",
				"cyan", entry.Timestamp.Format("15:04:05"),
				entry.LevelStr, color, entry.Category, entry.Message)

			fmt.Fprint(a.logView, line)
			a.logView.ScrollToEnd()

			// Update status bar
			a.updateStatusBar()
		})
	}
}

// Run runs the TUI application
func (a *App) Run() error {
	return a.app.Run()
}

// Helper functions

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
