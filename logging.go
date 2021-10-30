package main

import (
	"io/ioutil"
	"log/syslog"
	"os"

	lrh_gl "github.com/gemnasium/logrus-graylog-hook/v3"
	"github.com/sirupsen/logrus"
	lrh_sl "github.com/sirupsen/logrus/hooks/syslog"
	lrh_wr "github.com/sirupsen/logrus/hooks/writer"
)

var (
	// The logging context.
	log *logrus.Entry
)

// Configure the log level
func toLogLevel(cliLevel string) logrus.Level {
	if cliLevel == "" {
		return logrus.InfoLevel
	}
	lvl, err := logrus.ParseLevel(cliLevel)
	if err == nil {
		return lvl
	}
	log.WithField("level", cliLevel).Warning("Invalid log level on command line")
	return logrus.InfoLevel
}

// Add a file writer hook to the logging library.
func configureLogFile(path string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.Logger.AddHook(&lrh_wr.Hook{
			Writer:    file,
			LogLevels: logrus.AllLevels,
		})
	} else {
		log.WithFields(logrus.Fields{
			"error": err,
			"file":  path,
		}).Error("Could not open log file")
	}
}

// Configure the logging library based on the various command line flags.
func configureLogging(flags cliFlags) error {
	log = logrus.NewEntry(logrus.New())
	log.Logger.SetFormatter(&logrus.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	log.Logger.SetLevel(toLogLevel(flags.logLevel))
	if flags.logFile != "" {
		configureLogFile(flags.logFile)
	}
	if flags.logGraylog != "" {
		log.Logger.AddHook(lrh_gl.NewGraylogHook(flags.logGraylog, nil))
	}
	if flags.logSyslog {
		hook, err := lrh_sl.NewSyslogHook("", "", syslog.LOG_DEBUG, "fetchcert")
		if err != nil {
			return err
		}
		log.Logger.AddHook(hook)
	}
	if flags.quiet {
		log.Logger.SetOutput(ioutil.Discard)
	}
	return nil
}
