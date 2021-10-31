package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"

	valid "github.com/asaskevich/govalidator"
	"gopkg.in/yaml.v2"
)

type (
	/*                    *
	 * CONFIGURATION DATA *
	 *                    */

	// UNIX socket configuration. This includes the full path to the socket
	// as well as the group name and mode.
	tSocketConfig struct {
		Path  string      `yaml:"path"`
		Group string      `yaml:"group"`
		Mode  os.FileMode `yaml:"mode"`
	}

	// LDAP connection configuration, used for servers and as a way to specify
	// defaults.
	tLdapConnectionConfig struct {
		Port         uint16 `yaml:"port"`
		TLS          string `yaml:"tls"`
		TLSNoVerify  bool   `yaml:"tls_skip_verify"`
		CaChain      string `yaml:"ca_chain"`
		BindUser     string `yaml:"bind_user"`
		BindPassword string `yaml:"bind_password"`
	}

	// LDAP server configuration. This defines how to connect to a
	// single, specific LDAP server.
	tLdapServerConfig struct {
		Host string `yaml:"host"`
		tLdapConnectionConfig
	}

	// LDAP attributes and base DN configuration
	tLdapStructureConfig struct {
		BaseDN               string `yaml:"base_dn"`
		EndEntityCertificate string `yaml:"end_entity"`
		CACertificate        string `yaml:"ca_certificate"`
		CAChaining           string `yaml:"ca_chaining"`
	}

	// LDAP configuration: LDAP structure, connection defaults and server
	// connections.
	tLdapConfig struct {
		Structure tLdapStructureConfig  `yaml:"structure"`
		Defaults  tLdapConnectionConfig `yaml:"defaults"`
		Servers   []tLdapServerConfig   `yaml:"servers"`
	}

	// Certificate file configuration.
	tCertificateFileConfig struct {
		Path           string      `yaml:"path"`
		Mode           os.FileMode `yaml:"mode"`
		Owner          string      `yaml:"owner"`
		Group          string      `yaml:"group"`
		PrependFiles   []string    `yaml:"prepend_files"`
		Certificate    string      `yaml:"certificate"`
		CACertificates []string    `yaml:"ca"`
		CAChainOf      string      `yaml:"ca_chain_of"`
		Reverse        bool        `yaml:"reverse"`
		AppendFiles    []string    `yaml:"append_files"`
		AfterUpdate    []string    `yaml:"after_update"`
	}

	// Main configuration.
	tConfiguration struct {
		Socket       tSocketConfig            `yaml:"socket"`
		LdapConfig   tLdapConfig              `yaml:"ldap"`
		Certificates []tCertificateFileConfig `yaml:"certificates"`
	}
)

// Helper function that checks whether a string corresponds to a group name.
func isValidGroup(name string) bool {
	group, err := user.LookupGroup(name)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(group.Gid)
	return err == nil
}

// Helper function that checks whether a string corresponds to a user name.
func isValidUser(name string) bool {
	user, err := user.Lookup(name)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(user.Uid)
	return err == nil
}

// Validate the UNIX socket configuration
func (c *tSocketConfig) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("Missing socket path.")
	}
	if !valid.IsUnixFilePath(c.Path) {
		return fmt.Errorf("Socket path '%s' is invalid.", c.Path)
	}
	if c.Group != "" && !isValidGroup(c.Group) {
		return fmt.Errorf("Invalid group '%s'", c.Group)
	}
	return nil
}

// Check the LDAP structure configuration.
func (c *tLdapStructureConfig) Validate() error {
	if c.EndEntityCertificate == "" {
		return fmt.Errorf("Missing end entity certificate attribute name.")
	}
	if c.CACertificate == "" {
		return fmt.Errorf("Missing CA certificate attribute name.")
	}
	return nil
}

// Check the TLS field in LDAP configuration entries. If no port is specified,
// default it based on the TLS field.
func (c *tLdapConnectionConfig) Validate() error {
	if c.TLS != "yes" && c.TLS != "starttls" && c.TLS != "no" {
		return fmt.Errorf("Invalid TLS mode '%s' (valid values are 'yes', 'starttls' and 'no'", c.TLS)
	}
	if c.CaChain != "" {
		data, err := ioutil.ReadFile(c.CaChain)
		if err != nil {
			return fmt.Errorf("Unable to read CA chain from '%s': %w", c.CaChain, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("Could not parse CA chain PEM from '%s'.", c.CaChain)
		}
	}
	return nil
}

// Copy defaults into a LDAP server configuration entry.
func (c *tLdapServerConfig) ApplyDefaults(dft tLdapConnectionConfig) {
	if c.Port == 0 {
		c.Port = dft.Port
	}
	if c.TLS == "" {
		c.TLS = dft.TLS
	}
	// FIXME: I have no clue how I should handle TLSNoVerify
	if c.CaChain == "" {
		c.CaChain = dft.CaChain
	}
	if c.BindUser == "" {
		c.BindUser = dft.BindUser
	}
	if c.BindPassword == "" {
		c.BindPassword = dft.BindPassword
	}

	// Default port based on TLS mode
	if c.Port == 0 {
		if c.TLS == "starttls" {
			c.Port = 636
		} else {
			c.Port = 389
		}
	}
}

// Validate a LDAP server configuration record.
func (c *tLdapServerConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("No host name in LDAP server configuration.")
	}
	if !valid.IsHost(c.Host) {
		return fmt.Errorf("Invalid host name '%s'", c.Host)
	}
	return c.tLdapConnectionConfig.Validate()
}

// Validate the LDAP configuration
func (c *tLdapConfig) Validate() error {
	err := c.Structure.Validate()
	if err != nil {
		return err
	}
	err = c.Defaults.Validate()
	if err != nil {
		return err
	}
	if len(c.Servers) == 0 {
		return fmt.Errorf("No LDAP servers have been configured.")
	}
	for i := range c.Servers {
		c.Servers[i].ApplyDefaults(c.Defaults)
		err = c.Servers[i].Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Check that a list of files contains only valid paths
func checkFileList(files []string) error {
	for _, path := range files {
		if !valid.IsUnixFilePath(path) {
			return fmt.Errorf("Invalid path '%s'", path)
		}
	}
	return nil
}

// Validate a certificate file configuration entry
func (c *tCertificateFileConfig) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("Certificate file entry has no path.")
	}
	if !valid.IsUnixFilePath(c.Path) {
		return fmt.Errorf("Certificate file path '%s' is invalid.", c.Path)
	}
	if c.Owner != "" && !isValidUser(c.Owner) {
		return fmt.Errorf("Unknown user '%s'", c.Owner)
	}
	if c.Group != "" && !isValidGroup(c.Group) {
		return fmt.Errorf("Invalid group '%s'", c.Group)
	}
	err := checkFileList(c.PrependFiles)
	if err != nil {
		return err
	}
	for _, path := range c.PrependFiles {
		if !valid.IsUnixFilePath(path) {
			return fmt.Errorf("Invalid path '%s'", path)
		}
	}
	if c.Certificate == "" && len(c.CACertificates) == 0 && c.CAChainOf == "" {
		return fmt.Errorf("Certificate path '%s' has no certificate or CA chain", c.Path)
	}
	if c.CAChainOf != "" && len(c.CACertificates) != 0 {
		return fmt.Errorf("Certificate path '%s' uses both 'ca' and 'ca_chain_of'", c.Path)
	}
	err = checkFileList(c.AppendFiles)
	if err != nil {
		return err
	}
	return nil
}

// Validate the configuration
func (c *tConfiguration) Validate() error {
	err := c.Socket.Validate()
	if err != nil {
		return err
	}
	err = c.LdapConfig.Validate()
	if err != nil {
		return err
	}
	for _, cfc := range c.Certificates {
		err = cfc.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Create a configuration data structure containing default values.
func defaultConfiguration() tConfiguration {
	cfg := tConfiguration{}
	cfg.Socket.Mode = 0640
	cfg.LdapConfig.Defaults.TLS = "no"
	cfg.LdapConfig.Structure.CAChaining = "seeAlso"
	return cfg
}

// Load and check the configuration file
func loadConfiguration(file string) (tConfiguration, error) {
	cfg := defaultConfiguration()
	cfgData, err := ioutil.ReadFile(file)
	if err != nil {
		return cfg, fmt.Errorf("Could not load configuration: %w", err)
	}
	err = yaml.Unmarshal(cfgData, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("Could not parse configuration: %w", err)
	}
	err = cfg.Validate()
	return cfg, err
}
