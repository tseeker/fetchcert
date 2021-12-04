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

type tCommandType int

const (
	CMD_IGNORE tCommandType = iota
	CMD_QUIT
	CMD_RELOAD
	CMD_UPDATE
)

type (
	tCommand struct {
		CommandType tCommandType
		Force       bool
		Selector    string
	}

	// The state of the main server
	TServerState struct {
		// The path to the configuration file
		cfgFile string
		// The configuration
		config tConfiguration
		// The UNIX socket listener
		listener net.Listener
	}
)

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

func socketServer(cfg *tConfiguration, listener net.Listener) tCommandType {
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

func executeFromSocket(cfg *tConfiguration, conn net.Conn) tCommandType {
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
		success := executeUpdate(cfg, command.Selector, command.Force)
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

func parseCommand(n int, buf []byte) *tCommand {
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
			return &tCommand{CommandType: CMD_QUIT}
		} else if buf[0] == 'R' {
			return &tCommand{CommandType: CMD_RELOAD}
		}
	} else if n > 2 && buf[0] == 'U' {
		res := &tCommand{CommandType: CMD_UPDATE}
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

// Initialize server state
func InitServer(cfgFile string, config tConfiguration) TServerState {
	ss := TServerState{
		cfgFile: cfgFile,
		config:  config,
	}
	listener, err := initSocket(ss.config.Socket)
	if err != nil {
		log.WithField("error", err).Fatal("Failed to initialize socket.")
	}
	ss.listener = listener
	return ss
}

// Destroy the server
func (state *TServerState) Destroy() {
	state.listener.Close()
}

// Server main loop. Processes commands received from connections. Certificate
// update requests are processed directly, but Quit/Reload commands are
// propagated back to this loop and handled here.
func (state *TServerState) MainLoop() {
	for {
		cmd := socketServer(&state.config, state.listener)
		if cmd == CMD_QUIT {
			break
		} else if cmd != CMD_RELOAD {
			continue
		}

		new_cfg, err := LoadConfiguration(state.cfgFile)
		if err != nil {
			log.WithField("error", err).Error("Failed to load updated configuration.")
			continue
		}

		replace_ok := true
		if new_cfg.Socket.Path != state.config.Socket.Path {
			new_listener, err := initSocket(new_cfg.Socket)
			if err != nil {
				log.WithField("error", err).Error("Failed to initialize new server socket.")
				replace_ok = false
			} else {
				state.listener.Close()
				state.listener = new_listener
			}
		}
		if replace_ok {
			state.config = new_cfg
			log.Info("Configuration reloaded")
		}
	}
}
