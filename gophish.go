package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/gophish/gophish/config"
	"github.com/gophish/gophish/controllers"
	"github.com/gophish/gophish/dialer"
	"github.com/gophish/gophish/imap"
	glog "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/webhook"
)

const (
	modeAll   = "all"
	modeAdmin = "admin"
	modePhish = "phish"
)

var (
	configPath    = kingpin.Flag("config", "Path to config.json").Default("./config.json").String()
	disableMailer = kingpin.Flag("disable-mailer", "Disable built-in mailer").Bool()
	mode          = kingpin.Flag("mode", fmt.Sprintf("Run mode: %s, %s, %s", modeAll, modeAdmin, modePhish)).Default("all").Enum(modeAll, modeAdmin, modePhish)
)

func readVersionFile() string {
	path, err := filepath.Abs("./VERSION")
	if err != nil {
		log.Fatalf("[INIT] Failed to get absolute path for VERSION file: %v", err)
	}
	versionBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[INIT] Could not read VERSION file: %v", err)
	}
	return string(versionBytes)
}

func setupSignalHandler(shutdownFunc func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-sigs
		log.Printf("[SYSTEM] Signal %s received, shutting down gracefully...", sig)
		shutdownFunc()
		os.Exit(0)
	}()
}

func loadConfiguration(path string) *config.Config {
	conf, err := config.LoadConfig(path)
	if err != nil {
		log.Fatalf("[CONFIG] Failed to load configuration: %v", err)
	}
	if conf.ContactAddress == "" {
		log.Printf("[CONFIG] Warning: 'contact_address' not set in config.json")
	}
	return conf
}

func main() {
	version := readVersionFile()
	kingpin.Version(version)
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Parse()

	conf := loadConfiguration(*configPath)
	config.Version = version // still global, but we'll remove this later if you want full isolation

	// Setup logging
	if err := glog.Setup(conf.Logging); err != nil {
		log.Fatalf("[LOGGING] Failed to initialize logger: %v", err)
	}

	// Restrict outbound network connections
	dialer.SetAllowedHosts(conf.AdminConf.AllowedInternalHosts)
	webhook.SetTransport(&http.Transport{
		DialContext: dialer.Dialer().DialContext,
	})

	if err := models.Setup(conf); err != nil {
		log.Fatalf("[DB] Failed to initialize database/models: %v", err)
	}

	if err := models.UnlockAllMailLogs(); err != nil {
		log.Fatalf("[DB] Failed to unlock maillogs: %v", err)
	}

	adminOptions := []controllers.AdminServerOption{}
	if *disableMailer {
		log.Println("[CONFIG] Mailer disabled by --disable-mailer flag")
		adminOptions = append(adminOptions, controllers.WithWorker(nil))
	}

	adminServer := controllers.NewAdminServer(conf.AdminConf, adminOptions...)
	middleware.Store.Options.Secure = conf.AdminConf.UseTLS

	phishServer := controllers.NewPhishingServer(conf.PhishConf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *mode == modeAdmin || *mode == modeAll {
		go func() {
			log.Println("[STARTUP] Admin server starting...")
			adminServer.Start()
		}()
		go func() {
			log.Println("[STARTUP] IMAP monitor started...")
			imap.NewMonitor().Start() // Optional: allow config flag to disable
		}()
	}

	if *mode == modePhish || *mode == modeAll {
		go func() {
			log.Println("[STARTUP] Phishing server starting...")
			phishServer.Start()
		}()
	}

	setupSignalHandler(func() {
		if *mode == modeAdmin || *mode == modeAll {
			log.Println("[SHUTDOWN] Shutting down Admin server...")
			adminServer.Shutdown()
			log.Println("[SHUTDOWN] Stopping IMAP monitor...")
			imap.NewMonitor().Shutdown()
		}
		if *mode == modePhish || *mode == modeAll {
			log.Println("[SHUTDOWN] Shutting down Phishing server...")
			phishServer.Shutdown()
		}
	})

	// Wait indefinitely (or extend for healthcheck integration later)
	select {}
}
