package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckConfigCommandValidatesWithoutStartingListeners(t *testing.T) {
	key, _ := testKey()
	config := Config{
		DataDir: filepath.Join(t.TempDir(), "state"),
		Listen:  "127.0.0.1:0",
		TLSCert: "/etc/gbf-power/control/tls.crt",
		TLSKey:  "/etc/gbf-power/control/tls.key",
		Node:    Node{Host: "192.0.2.20", Port: 2222, Username: "gbfdevice", HostKey: key},
	}
	contents, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "control.json")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"check-config", "--config", path}); err != nil {
		t.Fatalf("valid offline configuration was rejected: %v", err)
	}
	if _, err := os.Stat(config.DataDir); !os.IsNotExist(err) {
		t.Fatalf("offline validation created state: %v", err)
	}
}

func TestCheckConfigCommandRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"check-config", "--config", path}); err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}
