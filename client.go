package main

import (
	"net"

	"github.com/sirupsen/logrus"
)

// Client runtime data
type TClient struct {
	config tConfiguration
}

// Initialize the client's state.
func InitClient(config tConfiguration) TClient {
	if config.Socket == nil {
		log.Fatal("Cannot run in client mode without a socket configuration")
	}
	return TClient{
		config: config,
	}
}

// Connect to the UNIX socket. Terminate the program with an error if connection
// fails.
func (c *TClient) getConnection() net.Conn {
	conn, err := net.Dial("unix", c.config.Socket.Path)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
			"path":  c.config.Socket.Path,
		}).Fatal("Could not connect to the UNIX socket")
	}
	return conn
}

// Send a string to the UNIX socket. Terminate the program with an error if
// some form of IO error occurs.
func (c *TClient) send(conn net.Conn, data string) {
	_, err := conn.Write([]byte(data))
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
			"path":  c.config.Socket.Path,
			"data":  data,
		}).Fatal("Could not write to the UNIX socket")
	}
}

// Send a command to the server then disconnect.
func (c *TClient) SendCommand(command string) {
	conn := c.getConnection()
	defer conn.Close()
	c.send(conn, command)
}

// Request an update by sending the selector and force flag to the server, then
// wait for the server to respond. Returns true if the server responded that the
// updates were executed without problem.
func (c *TClient) RequestUpdate(selector string, force bool) bool {
	command := "U"
	if force {
		command += "!"
	} else {
		command += " "
	}
	command += selector

	conn := c.getConnection()
	defer conn.Close()
	c.send(conn, command)

	buf := make([]byte, 2)
	nr, err := conn.Read(buf)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
			"path":  c.config.Socket.Path,
		}).Fatal("Could not read server response from the UNIX socket")
	}
	if nr != 1 {
		log.WithFields(logrus.Fields{
			"path": c.config.Socket.Path,
		}).Fatal("Invalid response from server")
	}
	return buf[0] == 49
}
