package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

type (
	tUpdate struct {
		// The current configuration
		config *tConfiguration
		// The selector for this update
		selector string
		// Whether the update must be forced.
		force bool
		// Certificate builders for each configured certificate file
		builders []*tCertificateBuilder
		// Whether errors occurred during the update.
		errors bool
	}
)

// Start a new update, based on the specified configuration. The update's
// parameters (selector and force flag) will be stored as well.
func NewUpdate(cfg *tConfiguration, selector string, force bool) tUpdate {
	return tUpdate{
		config:   cfg,
		selector: selector,
		force:    force,
		builders: make([]*tCertificateBuilder, len(cfg.Certificates)),
	}
}

// Execute the update. Builders will be initialized and filtered based on the
// selector, then used to write the certificates to files. After that, commands
// and handlers will be executed.
func (u *tUpdate) Execute() bool {
	u.initBuilders()
	u.writeFiles()
	u.runPreCommands()
	handlers := u.enumerateHandlers()
	failedHandlers := u.runHandlers(handlers)
	u.disableBuildersWithFailedHandlers(failedHandlers)
	u.runPostCommands()
	return !u.errors
}

// Initialise builders for all certificates that need to be updated. If errors
// occur while preparing one of the certificates, or if it doesn't match the
// selector, the builder will not be kept.
func (u *tUpdate) initBuilders() {
	ldap := NewLdapConnection(u.config.LdapConfig)
	if ldap == nil {
		return
	}
	defer ldap.Close()
	for i := range u.config.Certificates {
		builder := NewCertificateBuilder(ldap, &u.config.Certificates[i])
		err := builder.Build()
		if err != nil {
			log.WithField("error", err).Error(
				"Failed to build data for certificate '",
				builder.Config.Path, "'",
			)
			u.errors = true
		} else if builder.SelectorMatches(u.selector) {
			u.builders[i] = builder
		}
	}
}

// Write certificates to disk and set file ownership/privileges for all builders
// that were initalised.
func (u *tUpdate) writeFiles() {
	for i, builder := range u.builders {
		if builder == nil {
			continue
		}

		if builder.MustWrite(u.force) {
			err := builder.WriteFile()
			if err != nil {
				log.WithField("error", err).Error(
					"Failed to write '",
					builder.Config.Path, "'",
				)
				u.errors = true
				continue
			}
		}
		err := builder.UpdatePrivileges()
		if err != nil {
			log.WithField("error", err).Error(
				"Failed to update privileges on '",
				builder.Config.Path, "'",
			)
			u.errors = true
			continue
		}
		if !builder.Changed() {
			u.builders[i] = nil
		}
	}
}

// Run pre-commands for all builders.
func (u *tUpdate) runPreCommands() {
	for i, builder := range u.builders {
		if builder == nil {
			continue
		}

		commands := u.config.Certificates[i].AfterUpdate.PreCommands
		if len(commands) == 0 {
			continue
		}

		l := log.WithField("file", u.config.Certificates[i].Path)
		l.Info("Running pre-commands")
		timeout := u.config.CmdTimeout
		if u.config.Certificates[i].AfterUpdate.CmdTimeout != nil {
			timeout = *u.config.Certificates[i].AfterUpdate.CmdTimeout
		}
		err := u.runCommands(timeout, commands, l)
		if err == nil {
			continue
		}

		l.WithField("error", err).Error("Failed to run pre-commands")
		u.builders[i] = nil
		u.errors = true
	}
}

// Returns a list of all handlers that must be executed based on the builders
// still listed as active.
func (u *tUpdate) enumerateHandlers() []string {
	handlers := make(map[string]bool)
	for i, builder := range u.builders {
		if builder == nil {
			continue
		}
		for _, handler := range u.config.Certificates[i].AfterUpdate.Handlers {
			handlers[handler] = true
		}
	}
	hdl_list := []string{}
	for handler := range handlers {
		hdl_list = append(hdl_list, handler)
	}
	return hdl_list
}

// Execute commands for all listed handlers, returning a map of handlers that
// failed to execute.
func (u *tUpdate) runHandlers(handlers []string) map[string]bool {
	failures := make(map[string]bool)
	for _, handler := range handlers {
		l := log.WithField("handler", handler)
		l.Info("Running handler")
		timeout := u.config.CmdTimeout
		if ht, exists := u.config.HandlerTimeouts[handler]; exists {
			timeout = ht
		}
		err := u.runCommands(timeout, u.config.Handlers[handler], l)
		if err == nil {
			continue
		}
		l.WithField("error", err).Error("Failed to run handler commands")
		failures[handler] = true
		u.errors = true
	}
	return failures
}

// Disable builders that have one of the failed handlers in their list of
// handlers.
func (u *tUpdate) disableBuildersWithFailedHandlers(failedHandlers map[string]bool) {
	for i, builder := range u.builders {
		if builder == nil {
			continue
		}
		for _, handler := range u.config.Certificates[i].AfterUpdate.Handlers {
			if _, exists := failedHandlers[handler]; exists {
				log.WithFields(logrus.Fields{
					"handler": handler,
					"file":    u.config.Certificates[i].Path,
				}).Debug("Disabling builder due to failed handler")
				u.builders[i] = nil
				break
			}
		}
	}
}

// Run post-commands for all builders.
func (u *tUpdate) runPostCommands() {
	for i, builder := range u.builders {
		if builder == nil {
			continue
		}

		commands := u.config.Certificates[i].AfterUpdate.PostCommands
		if len(commands) == 0 {
			continue
		}

		l := log.WithField("file", u.config.Certificates[i].Path)
		l.Info("Running post-commands")
		timeout := u.config.CmdTimeout
		if u.config.Certificates[i].AfterUpdate.CmdTimeout != nil {
			timeout = *u.config.Certificates[i].AfterUpdate.CmdTimeout
		}
		err := u.runCommands(timeout, commands, l)
		if err == nil {
			continue
		}

		l.WithField("error", err).Error("Failed to run post-commands")
		u.builders[i] = nil
		u.errors = true
	}
}

// Run a list of commands.
func (u *tUpdate) runCommands(timeout int, commands []string, log *logrus.Entry) error {
	for i := range commands {
		err := u.runCommand(timeout, commands[i], log)
		if err != nil {
			return fmt.Errorf(
				"Failed while executing command '%s': %w",
				commands[i], err,
			)
		}
	}
	return nil
}

// Run a command through the `sh` shell.
func (b *tUpdate) runCommand(timeout int, command string, log *logrus.Entry) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	log = log.WithFields(logrus.Fields{
		"command": command,
		"timeout": timeout,
	})
	log.Debug("Executing command")
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if len(output) != 0 {
		if utf8.Valid(output) {
			log = log.WithField("output", string(output))
		} else {
			log = log.WithField("output", string(output))
		}
	}
	if err == nil {
		log.Info("Command executed")
	} else {
		log.WithField("error", err).Error("Command failed")
	}
	return err
}

func executeUpdate(cfg *tConfiguration, selector string, force bool) bool {
	ex := NewUpdate(cfg, selector, force)
	return ex.Execute()
}
