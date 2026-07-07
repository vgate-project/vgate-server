// Package cmd provides the CLI commands for vgate using cobra.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vgate-project/vgate-server/api"
	"github.com/vgate-project/vgate-server/config"
	"github.com/vgate-project/vgate-server/model"
	"github.com/vgate-project/vgate-server/proxy"
	"github.com/vgate-project/vgate-server/proxy/vless"
	"github.com/vgate-project/vgate-server/transport/xraybridge"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cfgFile string

// rootCmd is the base command — starts the VGate server.
var rootCmd = &cobra.Command{
	Use:   "vgate",
	Short: "VGate VLESS Backend",
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yml)")
}

// Execute runs the root command. This is the single entry point called
// from main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	// 1. Load local base configuration
	localCfg, err := config.LoadLocalConfig(cfgFile)
	if err != nil {
		log.Errorf("Failed to load config: %v", err)
		os.Exit(1)
	}

	// Apply configured log level (falls back to info on invalid value).
	if lvl := localCfg.LogLevel; lvl != "" {
		if level, err := log.ParseLevel(lvl); err != nil {
			log.Warnf("invalid log_level %q, falling back to info: %v", lvl, err)
		} else {
			log.SetLevel(level)
		}
	}

	// Configure xray-core's internal logger once at startup (falls back to
	// warning on invalid value). Not re-applied on hot-reload.
	if err := xraybridge.InitLogger(localCfg.LogLevel); err != nil {
		log.Warnf("invalid log_level %q, falling back to warning for xray-core logs: %v", localCfg.LogLevel, err)
		_ = xraybridge.InitLogger("warning")
	}

	log.Infof("Starting VGate with Admin API: %s", localCfg.AdminAPI)

	// 2. Initialize API client and VLESS server
	baseURL := strings.TrimRight(localCfg.AdminAPI, "/") + "/api/v1/server"
	client := api.NewClient(baseURL, localCfg.NodeID, localCfg.NodeToken)
	var server proxy.Inbound = vless.NewServer()

	// 3. Initial sync
	pendingTraffic := make(map[string]*model.UserTraffic)
	sync(client, server, pendingTraffic)

	// 4. Start VLESS server
	go server.Start()

	// 5. Periodic pull and hot-reload
	ticker := time.NewTicker(time.Duration(localCfg.SyncInterval) * time.Second)
	log.Infof("Hot-reload scheduler started: interval %d seconds", localCfg.SyncInterval)

	for range ticker.C {
		sync(client, server, pendingTraffic)
	}
}

func sync(client *api.Client, server proxy.Inbound, pendingTraffic map[string]*model.UserTraffic) {
	log.Debug("Syncing config and users from manager...")

	cfg, err := client.FetchConfig()
	switch {
	case errors.Is(err, api.ErrNotModified):
		log.Debug("Config unchanged (304), skip reload")
	case err != nil:
		log.Errorf("Error fetching config: %v", err)
	default:
		server.UpdateConfig(cfg)
	}

	users, err := client.FetchUsers()
	switch {
	case errors.Is(err, api.ErrNotModified):
		log.Debug("Users unchanged (304), skip update")
	case err != nil:
		log.Errorf("Error fetching users: %v", err)
	default:
		server.UpdateUsers(users)
	}

	// 6. Traffic reporting
	stats := server.GetAndResetTraffic()
	for _, s := range stats {
		if t, ok := pendingTraffic[s.Email]; ok {
			t.Up += s.Up
			t.Down += s.Down
		} else {
			pendingTraffic[s.Email] = &model.UserTraffic{
				Email: s.Email,
				Up:    s.Up,
				Down:  s.Down,
			}
		}
	}

	if len(pendingTraffic) > 0 {
		reportList := make([]model.UserTraffic, 0, len(pendingTraffic))
		for _, t := range pendingTraffic {
			reportList = append(reportList, *t)
		}
		err := client.ReportTraffic(reportList)
		if err != nil {
			log.Errorf("Failed to report traffic: %v. Data will be kept for next report.", err)
		} else {
			log.Debugf("Successfully reported traffic for %d users", len(pendingTraffic))
			for k := range pendingTraffic {
				delete(pendingTraffic, k)
			}
		}
	}
}
