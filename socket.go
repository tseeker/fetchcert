package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

type TCommandType int

const (
	CMD_IGNORE TCommandType = iota
	CMD_QUIT
	CMD_RELOAD
	CMD_UPDATE
)

type TCommand struct {
	CommandType TCommandType
	Force       bool
	Selector    string
}

func configureSocket(cfg tSocketConfig) error {
	if cfg.Group != "" {
		group, err := user.LookupGroup(cfg.Group)
		if err != nil {
			return fmt.Errorf("Group %s not found: %w", cfg.Group, err)
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			return fmt.Errorf("Group %s has non-numeric GID %s", cfg.Group, group.Gid)
		}
		err = os.Chown(cfg.Path, -1, gid)
		if err != nil {
			return fmt.Errorf("Cannot change group on UNIX socket: %w", err)
		}
	}

	if cfg.Mode != 0 {
		err := os.Chmod(cfg.Path, cfg.Mode)
		if err != nil {
			return fmt.Errorf("Cannot set UNIX socket access mode: %w", err)
		}
	}

	return nil
}

func initSocket(cfg tSocketConfig) (net.Listener, error) {
	listener, err := net.Listen("unix", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("Cannot listen on UNIX socket at %s: %w", cfg.Path, err)
	}
	err = configureSocket(cfg)
	if err != nil {
		listener.Close()
		return nil, err
	}
	log.WithField("path", cfg.Path).Info("UNIX socket created")
	return listener, nil
}

func socketServer(cfg *tConfiguration, listener net.Listener) TCommandType {
	for {
		fd, err := listener.Accept()
		if err != nil {
			log.WithField("error", err).Fatal("Error while waiting for connections.")
		}
		cmd := executeFromSocket(cfg, fd)
		if cmd != CMD_IGNORE {
			return cmd
		}
	}
}

func executeFromSocket(cfg *tConfiguration, conn net.Conn) TCommandType {
	defer conn.Close()
	log.Debug("Received connection")

	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		log.WithField("error", err).Error("Could not read from socket")
		return CMD_IGNORE
	}
	command := parseCommand(n, buf)
	if command == nil {
		return CMD_IGNORE
	}
	if command.CommandType == CMD_UPDATE {
		log.WithFields(logrus.Fields{
			"force":    command.Force,
			"selector": command.Selector,
		}).Info("Update request received")
		success := executeUpdate(cfg, command)
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		var bval byte
		if success {
			bval = '1'
		} else {
			bval = '0'
		}
		conn.Write([]byte{bval})
		return CMD_IGNORE
	}
	return command.CommandType
}

func parseCommand(n int, buf []byte) *TCommand {
	if n == 512 {
		log.Warn("Too much data received")
		return nil
	}
	if n == 0 {
		log.Warn("Not enough data received")
		return nil
	}
	if n == 1 {
		if buf[0] == 'Q' {
			return &TCommand{CommandType: CMD_QUIT}
		} else if buf[0] == 'R' {
			return &TCommand{CommandType: CMD_RELOAD}
		}
	} else if n > 2 && buf[0] == 'U' {
		res := &TCommand{CommandType: CMD_UPDATE}
		if buf[1] == '!' {
			res.Force = true
		}
		if utf8.Valid(buf[2:]) {
			res.Selector = string(buf[2:n])
			return res
		}
	}
	log.Warn("Invalid command received")
	return nil
}

func executeUpdate(cfg *tConfiguration, cmd *TCommand) bool {
	conn := NewLdapConnection(cfg.LdapConfig)
	if conn == nil {
		return false
	}
	defer conn.Close()

	had_errors := false
	for i := range cfg.Certificates {
		// TODO apply selector
		builder := NewCertificateBuilder(conn, &cfg.Certificates[i])
		err := builder.Build()
		if err != nil {
			log.WithField("error", err).Error("Failed to build data for certificate '", cfg.Certificates[i].Path, "'")
			had_errors = true
			continue
		}
		if builder.MustWrite() || cmd.Force {
			err := builder.WriteFile()
			if err != nil {
				log.WithField("error", err).Error("Failed to write '", cfg.Certificates[i].Path, "'")
				had_errors = true
				continue
			}
		}
		err = builder.UpdatePrivileges()
		if err != nil {
			log.WithField("error", err).Error("Failed to update privileges on '", cfg.Certificates[i].Path, "'")
			had_errors = true
			continue
		}
		err = builder.RunCommandsIfChanged()
		if err != nil {
			log.WithField("error", err).Error("Failed to run commands after update of '", cfg.Certificates[i].Path, "'")
			had_errors = true
		}
	}
	return !had_errors
}
