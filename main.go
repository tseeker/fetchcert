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
		// Mode to run as. May be either standalone (executes an update
		// then quits), client (connects to the server and requests an
		// update) or server (runs the server in the foreground).
		runMode string
		// When running in client mode, if this is set to a string, it
		// will be interpreted as a command to send to the server.
		// Supported commands are 'Q' (quit) and 'R' (reload
		// configuration)
		command string
		// The selector to use when running the updates. Only meaningful
		// if running in client or standalone mode.
		selector string
		// Whether updates should be forced. Only meaningful if running
		// in client or standalone mode.
		force bool
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

	golf.StringVarP(&flags.cfgFile, 'c', "config", "/etc/fetch-certificates.yml",
		"Path to the configuration file.")
	golf.StringVarP(&flags.command, 'C', "command", "",
		"Send a command to the server instead of requesting an "+
			"update. Only meaningful in client mode. Command may be "+
			"Q (quit) or R (reload configuration).")
	golf.BoolVarP(&flags.force, 'f', "force", false,
		"Force update of selected certificates. Only meaningful in "+
			"client or standalone mode.")
	golf.StringVarP(&flags.logFile, 'F', "log-file", "",
		"Path to the log file.")
	golf.StringVarP(&flags.logGraylog, 'g', "log-graylog", "",
		"Log to Graylog server (format: <host>:<port>).")
	golf.BoolVarP(&help, 'h', "help", false,
		"Display command line help and exit.")
	golf.StringVarP(&flags.logLevel, 'l', "log-level", "info",
		"Log level to use.")
	golf.StringVarP(&flags.runMode, 'm', "mode", "standalone",
		"Mode of execution (client/server/[standalone])")
	golf.BoolVarP(&flags.quiet, 'q', "quiet", false,
		"Quiet mode; prevents logging to stderr.")
	golf.BoolVarP(&flags.logSyslog, 's', "syslog", false,
		"Log to local syslog.")
	golf.StringVarP(&flags.selector, 'u', "update", "*",
		"LDAP DN of the certificate to select, or '*' to update all "+
			"certificates.")

	golf.Parse()
	if help {
		golf.Usage()
		os.Exit(0)
	}
	return flags
}

func main() {
	flags := parseCommandLine()
	err := configureLogging(flags)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to configure logging.")
	}

	cfg, err := LoadConfiguration(flags.cfgFile)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to load initial configuration.")
	}

	if flags.runMode == "server" {
		server := InitServer(flags.cfgFile, cfg)
		defer server.Destroy()
		server.MainLoop()

	} else if flags.runMode == "standalone" {
		result := executeUpdate(&cfg, flags.selector, flags.force)
		if result {
			log.Debug("Update successful")
		} else {
			log.Fatal("Update failed")
		}

	} else if flags.runMode == "client" {
		client := InitClient(cfg)
		if flags.command == "Q" || flags.command == "R" {
			client.SendCommand(flags.command)
		} else if flags.command != "" {
			log.WithField("command", flags.command).Fatal(
				"Unknown server command.")
		} else {
			result := client.RequestUpdate(flags.selector, flags.force)
			if result {
				log.Debug("Update successful")
			} else {
				log.Fatal("Update failed")
			}
		}

	} else {
		log.WithField("mode", flags.runMode).Fatal("Unknown execution mode.")
	}
}
