package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGatewayOnlyConfigValidation(t *testing.T) {
	c := GatewayOnlyConfig{Listen: ":2222", Username: "gbfdevice", HostKey: filepath.Join(t.TempDir(), "host"), Rules: filepath.Join(t.TempDir(), "rules.json"), NodeID: "osaka", ControlURL: "https://control.example:18444", ControlCertificateSHA256: strings.Repeat("a", 64), NodePrivateKey: filepath.Join(t.TempDir(), "node")}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid gateway config rejected: %v", err)
	}
	c.ControlURL = "http://control.example"
	if err := c.Validate(); err == nil {
		t.Fatal("unencrypted control URL accepted")
	}
}
func TestGatewayOnlyConfigAcceptsTokyoCN2Node(t *testing.T) {
	c := GatewayOnlyConfig{Listen: ":2222", Username: "gbfdevice", HostKey: filepath.Join(t.TempDir(), "host"), Rules: filepath.Join(t.TempDir(), "rules.json"), NodeID: "tokyo_cn2", ControlURL: "https://control.example:18444", ControlCertificateSHA256: strings.Repeat("a", 64), NodePrivateKey: filepath.Join(t.TempDir(), "node")}
	if err := c.Validate(); err != nil {
		t.Fatalf("Tokyo CN2 gateway config rejected: %v", err)
	}
}

func TestReadNodeIdentityAcceptsOpenSSHEd25519PrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readNodeIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Public().(ed25519.PublicKey).Equal(privateKey.Public()) {
		t.Fatal("loaded node identity does not match")
	}
}
