package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWindowsOpenSSHBlockedDomainInterop(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows OpenSSH deployment interoperability")
	}
	python, _ := filepath.Abs("../gbf-desktop/build-venv/Scripts/python.exe")
	helper, _ := filepath.Abs("../gbf-ops-deploy/tests/openssh_probe.py")
	if _, err := os.Stat(python); err != nil {
		t.Skip("desktop test Python unavailable")
	}
	f := newGatewayFixture(t)
	folder := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	public, err := exec.CommandContext(ctx, python, helper, "prepare", folder).CombinedOutput()
	if err != nil {
		t.Fatalf("temporary credential preparation failed: %v %s", err, public)
	}
	_, code, err := f.store.Create()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.access(code, strings.TrimSpace(string(public)), true); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(ctx, python, helper, "probe", folder, f.address, f.hostKey).CombinedOutput()
	if err != nil {
		t.Fatalf("real OpenSSH interoperability failed: %v %s", err, output)
	}
	if !strings.Contains(string(output), "OPENSSH_POLICY_AND_CONTROL_PASS") {
		t.Fatalf("no confirmed result: %s", output)
	}
	t.Log(strings.TrimSpace(string(output)))
}
