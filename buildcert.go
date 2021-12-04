package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

// Max supported CA chain length
const MAX_CA_CHAIN_LENGTH = 8

type (
	// Structure that describes the existing file for a certificate.
	tExistingFileInfo struct {
		owner uint32
		group uint32
		mode  os.FileMode
	}

	// Certificate building, including the configuration, LDAP connection,
	// and the array of chunks that's being built.
	tCertificateBuilder struct {
		// The certificate file's current configuration
		Config *tCertificateFileConfig
		// The LDAP connection to read data from
		conn *tLdapConn
		// The logger to use
		logger *logrus.Entry
		// The list of DNs that are involved in generating this certificate. If the
		// command has a non-'*' selector, the list will be checked for a value
		// matching the selector befor anything else is done.
		dnList []string
		// The various chunks of data that will be written to the resulting PEM file.
		// Each chunk corresponds to a PEM block.
		data [][]byte
		// The output text
		text []byte
		// Information about the current file, if it exists.
		existing *tExistingFileInfo
		// Was the certificate file replaced?
		changed bool
	}
)

// Initialize a certificate file building using a LDAP connection and
// certificate file configuration.
func NewCertificateBuilder(conn *tLdapConn, config *tCertificateFileConfig) *tCertificateBuilder {
	return &tCertificateBuilder{
		Config: config,
		conn:   conn,
		logger: log.WithField("file", config.Path),
		data:   make([][]byte, 0),
	}
}

// Build the certificate file's data, returning any error that occurs while
// reading the source data.
func (b *tCertificateBuilder) Build() error {
	b.logger.Debug("Checking for updates")
	err := b.appendPemFiles(b.Config.PrependFiles)
	if err != nil {
		return err
	}
	err = b.appendCertificate()
	if err != nil {
		return err
	}
	err = b.appendCaCertificates()
	if err != nil {
		return err
	}
	err = b.appendPemFiles(b.Config.AppendFiles)
	if err != nil {
		return err
	}
	if b.Config.Reverse {
		b.reverseChunks()
	}
	b.generateText()
	return nil
}

// Check whether a selector matches one of the current certificate file's DNs.
func (b *tCertificateBuilder) SelectorMatches(selector string) bool {
	if selector == "*" {
		return true
	}
	sel := strings.ToLower(selector)
	for _, v := range b.dnList {
		if strings.ToLower(v) == sel {
			return true
		}
	}
	b.logger.WithField("selector", selector).Debug("Selector does not match.")
	return false
}

// Check whether the data should be written to disk. This also caches the
// file's owner, group and mode. If the update is being forced it will return
// `true` even if nothing changed.
//
// Note: file information will be read even when updates are forced, because
// it is used later to set file privileges.
func (b *tCertificateBuilder) MustWrite(force bool) bool {
	info, err := os.Lstat(b.Config.Path)
	if err != nil {
		return true
	}

	sys_stat := info.Sys().(*syscall.Stat_t)
	eif := &tExistingFileInfo{}
	eif.mode = info.Mode()
	eif.owner = sys_stat.Uid
	eif.group = sys_stat.Gid
	b.existing = eif

	if force || sys_stat.Size != int64(len(b.text)) {
		return true
	}
	existing, err := ioutil.ReadFile(b.Config.Path)
	if err != nil {
		return true
	}
	for i, ch := range b.text {
		if ch != existing[i] {
			return true
		}
	}
	return false
}

// Write the file's data
func (b *tCertificateBuilder) WriteFile() error {
	log.WithField("file", b.Config.Path).Info("Writing certificate data to file")
	err := ioutil.WriteFile(b.Config.Path, b.text, b.Config.Mode)
	if err == nil {
		b.changed = true
	}
	return err
}

// Update the file's owner and group
func (b *tCertificateBuilder) UpdatePrivileges() error {
	update_mode := !b.changed && b.existing.mode != b.Config.Mode
	if update_mode {
		err := os.Chmod(b.Config.Path, b.Config.Mode)
		if err != nil {
			return err
		}
	}

	log := b.logger
	set_uid, set_gid := -1, -1
	if b.Config.Owner != "" {
		usr, err := user.Lookup(b.Config.Owner)
		if err != nil {
			return err
		}
		uid, err := strconv.Atoi(usr.Uid)
		if b.changed || b.existing == nil || b.existing.owner != uint32(uid) {
			set_uid = uid
			log = log.WithField("uid", set_uid)
		}
	}
	if b.Config.Group != "" {
		group, err := user.LookupGroup(b.Config.Group)
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(group.Gid)
		if b.changed || b.existing == nil || b.existing.group != uint32(gid) {
			set_gid = gid
			log = log.WithField("gid", set_gid)
		}
	}
	if set_gid != -1 || set_uid != -1 {
		log.Info("Updating file owner/group")
		err := os.Chown(b.Config.Path, set_uid, set_gid)
		if err == nil {
			b.changed = true
		}
		return err
	} else {
		b.changed = b.changed || update_mode
		log.Debug("No update to privileges")
		return nil
	}
}

// Did this certificate change in any way?
func (b *tCertificateBuilder) Changed() bool {
	return b.changed
}

// Run the commands from the pre_commands section of the configuration.
// This is only called if the certificate file has been modified in
// any way. Execution will stop at the first failure.
func (b *tCertificateBuilder) RunPreCommands() error {
	for i := range b.Config.AfterUpdate.PreCommands {
		err := b.RunCommand(i)
		if err != nil {
			return fmt.Errorf(
				"Failed while executing command '%s': %w",
				b.Config.AfterUpdate.PreCommands[i],
				err,
			)
		}
	}
	return nil
}

// Run a command through the `sh` shell.
func (b *tCertificateBuilder) RunCommand(pos int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log := b.logger.WithField("command", b.Config.AfterUpdate.PreCommands[pos])
	log.Debug("Executing command")
	cmd := exec.CommandContext(ctx, "sh", "-c", b.Config.AfterUpdate.PreCommands[pos])
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

// Append PEM files from a list.
func (b *tCertificateBuilder) appendPemFiles(files []string) error {
	for _, path := range files {
		var err error
		b.logger.WithField("source", path).Debug("Adding PEM file")
		err = b.appendPem(path)
		if err != nil {
			return err
		}
	}
	return nil
}

// Append a PEM file to the current list of data chunks
func (b *tCertificateBuilder) appendPem(input string) error {
	data, err := ioutil.ReadFile(input)
	if err != nil {
		return fmt.Errorf("Could not load '%s': %w", input, err)
	}
	rest := data
	hadBlock := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		hadBlock = true
		b.data = append(b.data, pem.EncodeToMemory(block))
	}
	if hadBlock {
		return nil
	} else {
		return fmt.Errorf("No PEM blocks found in '%s'", input)
	}
}

// Append the main, end-entity certificate from the LDAP
func (b *tCertificateBuilder) appendCertificate() error {
	if b.Config.Certificate != "" {
		dn := b.conn.BaseDN()
		if dn != "" {
			dn = "," + dn
		}
		dn = b.Config.Certificate + dn
		b.dnList = append(b.dnList, strings.ToLower(dn))
		b.logger.WithField("dn", dn).Debug("Adding EE certificate from LDAP")
		data, err := b.conn.GetEndEntityCertificate(dn)
		if err != nil {
			return err
		}
		b.data = append(b.data, data)
	}
	return nil
}

// Append all CA certificates, reading the list from the LDAP or from the
// configuration.
func (b *tCertificateBuilder) appendCaCertificates() error {
	if len(b.Config.CACertificates) != 0 {
		return b.appendListedCaCerts()
	} else if b.Config.CAChainOf != "" {
		return b.appendChainedCaCerts()
	} else {
		return nil
	}
}

// Append CA certificates based on a list of DNs
func (b *tCertificateBuilder) appendListedCaCerts() error {
	bdn := b.conn.BaseDN()
	if bdn != "" {
		bdn = "," + bdn
	}
	for _, dn := range b.Config.CACertificates {
		full_dn := dn + bdn
		b.dnList = append(b.dnList, strings.ToLower(full_dn))
		b.logger.WithField("dn", full_dn).Debug("Adding CA certificate from LDAP")
		data, _, err := b.conn.GetCaCertificate(full_dn)
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("No CA certificate at DN '%s'", full_dn)
		}
		b.data = append(b.data, data)
	}
	return nil
}

// Append CA certificates by following a chain starting at some DN
func (b *tCertificateBuilder) appendChainedCaCerts() error {
	nFound := 0
	dn := b.Config.CAChainOf
	if b.conn.BaseDN() != "" {
		dn = dn + "," + b.conn.BaseDN()
	}
	for {
		b.dnList = append(b.dnList, strings.ToLower(dn))
		data, nextDn, err := b.conn.GetCaCertificate(dn)
		if err != nil {
			return err
		}
		if nFound != 0 {
			if data == nil {
				return fmt.Errorf("No CA certificate at DN '%s'", dn)
			}
			b.logger.WithField("dn", dn).Debug("Adding CA certificate from LDAP chain")
			b.data = append(b.data, data)
		}
		if nextDn == "" {
			return nil
		}
		dn = nextDn
		nFound += 1
		if nFound == MAX_CA_CHAIN_LENGTH {
			return fmt.Errorf("DN '%s': CA chain length exceeded", dn)
		}
	}
}

// Reverse the chunks in the list
func (b *tCertificateBuilder) reverseChunks() {
	b.logger.Debug("Reversing PEM list")
	l := len(b.data) / 2
	for i := 0; i < l/2; i++ {
		j := l - i - 1
		b.data[i], b.data[j] = b.data[j], b.data[i]
	}
}

// Generate the final text of the file
func (b *tCertificateBuilder) generateText() {
	size := int64(0)
	for i := range b.data {
		size += int64(len(b.data[i]))
		if i != 0 && b.data[i-1][len(b.data[i-1])-1] != '\n' {
			size++
		}
	}
	b.text = make([]byte, size)
	pos := 0
	for i := range b.data {
		copied := copy(b.text[pos:], b.data[i])
		pos += copied
		if i != 0 && b.data[i-1][len(b.data[i-1])-1] != '\n' {
			b.text[pos] = '\n'
			pos++
		}
	}
	b.logger.WithField("size", size).Debug("Data generated")
}
