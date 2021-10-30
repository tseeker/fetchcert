package main

import (
	"fmt"
	"io/ioutil"
	"os"

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

func defaultConfiguration() tConfiguration {
	cfg := tConfiguration{}
	cfg.Socket.Mode = 0640
	cfg.LdapConfig.Defaults.Port = 389
	cfg.LdapConfig.Defaults.TLS = "no"
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

	return cfg, nil
}
