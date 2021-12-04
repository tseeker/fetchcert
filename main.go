package main

import (
	"os"

	"github.com/karrick/golf"
)

type (
	// This structure contains all values that may be set from the command line.
	tCliFlags struct {
		// The path to the configuration file.
		cfgFile string
		// Quiet mode. Will disable logging to stderr.
		quiet bool
		// The log level.
		logLevel string
		// A file to write logs into.
		logFile string
		// Graylog server to send logs to (using GELF/UDP). Format is <hostname>:<port>.
		logGraylog string
		// Send logs to syslog.
		logSyslog bool
	}
)

// Parse command line options.
func parseCommandLine() tCliFlags {
	var help bool
	flags := tCliFlags{}

	golf.StringVarP(&flags.cfgFile, 'c', "config", "/etc/fetch-certificates.yml", "Path to the configuration file.")
	golf.StringVarP(&flags.logFile, 'f', "log-file", "", "Path to the log file.")
	golf.StringVarP(&flags.logGraylog, 'g', "log-graylog", "", "Log to Graylog server (format: <host>:<port>).")
	golf.BoolVarP(&help, 'h', "help", false, "Display command line help and exit.")
	golf.StringVarP(&flags.logLevel, 'L', "log-level", "info", "Log level to use.")
	golf.BoolVarP(&flags.quiet, 'q', "quiet", false, "Quiet mode; prevents logging to stderr.")
	golf.BoolVarP(&flags.logSyslog, 's', "syslog", false, "Log to local syslog.")

	golf.Parse()
	if help {
		golf.Usage()
		os.Exit(0)
	}
	return flags
}

func main() {
	// This utility will load its configuration then start listening on
	// a UNIX socket. It will be handle messages that can :
	// - stop the program,
	// - update the configuration,
	// - check a single entry for replacement,
	// - check all entries for replacement.
	// Both check commands include a flag that will force replacement.

	flags := parseCommandLine()
	err := configureLogging(flags)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to configure logging.")
	}

	cfg, err := LoadConfiguration(flags.cfgFile)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to load initial configuration.")
	}

	listener, err := initSocket(cfg.Socket)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to initialize socket.")
	}
	defer listener.Close()
	for {
		cmd := socketServer(&cfg, listener)
		if cmd == CMD_QUIT {
			break
		} else if cmd == CMD_RELOAD {
			new_cfg, err := LoadConfiguration(flags.cfgFile)
			if err != nil {
				log.WithField("error", err).Error("Failed to load updated configuration.")
			} else {
				replace_ok := true
				if new_cfg.Socket.Path != cfg.Socket.Path {
					new_listener, err := initSocket(new_cfg.Socket)
					if err != nil {
						log.WithField("error", err).Error("Failed to initialize new server socket.")
						replace_ok = false
					} else {
						listener.Close()
						listener = new_listener
					}
				}
				if replace_ok {
					cfg = new_cfg
					log.Info("Configuration reloaded")
				}
			}
		}
	}
}
