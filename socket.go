package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
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

	err := os.Chmod(cfg.Path, cfg.Mode)
	if err != nil {
		return fmt.Errorf("Cannot set UNIX socket access mode: %w", err)
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
