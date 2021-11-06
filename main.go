package main

import (
	"os"

	"github.com/karrick/golf"
)

type (
	// This structure contains all values that may be set from the command line.
	cliFlags struct {
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
func parseCommandLine() cliFlags {
	var help bool
	flags := cliFlags{}

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

	cfg, err := loadConfiguration(flags.cfgFile)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to load initial configuration.")
	}

	listener, err := initSocket(cfg.Socket)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to initialize socket.")
	}
	listener.Close()

	conn := NewLdapConnection(cfg.LdapConfig)
	if conn == nil {
		return
	}
	defer conn.Close()
	for i := range cfg.Certificates {
		builder := NewCertificateBuilder(conn, &cfg.Certificates[i])
		err := builder.Build()
		if err != nil {
			log.WithField("error", err).Error("Failed to build data for certificate '", cfg.Certificates[i].Path, "'")
			continue
		}
		if builder.MustWrite() {
			err := builder.WriteFile()
			if err != nil {
				log.WithField("error", err).Error("Failed to write '", cfg.Certificates[i].Path, "'")
				continue
			}
		}
		err = builder.UpdatePrivileges()
		if err != nil {
			log.WithField("error", err).Error("Failed to update privileges on '", cfg.Certificates[i].Path, "'")
			continue
		}
		builder.RunCommandsIfChanged()
	}
}
