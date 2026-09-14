package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteAuthorityUsesPinnedSignedControlPlaneAndRenewsLease(t *testing.T) {
	store, _, _, code := fixture(t)
	devicePublic, _ := testKey()
	device, _, err := store.access(code, devicePublic, true)
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	control := NewNodeControl(store, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil)
	server := httptest.NewTLSServer(control)
	defer server.Close()
	digest := sha256.Sum256(server.Certificate().Raw)
	now := time.Now()
	authority, err := NewRemoteAuthority(RemoteAuthorityConfig{NodeID: "osaka", ControlURL: server.URL, CertificateSHA256: hex.EncodeToString(digest[:]), PrivateKey: nodePrivate})
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return now }

	got, ok := authority.AuthenticateKey(devicePublic)
	if !ok || got.ID != device.ID || got.LicenseID != device.LicenseID {
		t.Fatalf("unexpected remote auth: %+v %v", got, ok)
	}
	if err := store.Revoke(device.ID); err != nil {
		t.Fatal(err)
	}
	if !authority.ActiveDevice(device.ID) {
		t.Fatal("lease was not honored before expiry")
	}
	now = now.Add(31 * time.Second)
	if authority.ActiveDevice(device.ID) {
		t.Fatal("revoked device survived lease renewal")
	}
}
func TestRemoteAuthorityRejectsWrongCertificatePin(t *testing.T) {
	store, _, _, _ := fixture(t)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewTLSServer(NewNodeControl(store, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil))
	defer server.Close()
	authority, err := NewRemoteAuthority(RemoteAuthorityConfig{NodeID: "osaka", ControlURL: server.URL, CertificateSHA256: "0000000000000000000000000000000000000000000000000000000000000000", PrivateKey: nodePrivate})
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, _ := testKey()
	if _, ok := authority.AuthenticateKey(devicePublic); ok {
		t.Fatal("wrong certificate pin accepted")
	}
	if authority.Healthy() {
		t.Fatal("authority remained healthy after pin failure")
	}
}

func TestRemoteAuthorityAcceptsTokyoCN2NodeID(t *testing.T) {
	_, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, err := NewRemoteAuthority(RemoteAuthorityConfig{
		NodeID:            "tokyo_cn2",
		ControlURL:        "https://127.0.0.1:18444",
		CertificateSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		PrivateKey:        nodePrivate,
	})
	if err != nil {
		t.Fatalf("tokyo CN2 node ID rejected: %v", err)
	}
}

func TestRemoteAuthorityReportsSignedNodeMetrics(t *testing.T) {
	store, _, _, _ := fixture(t)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	selector := NewNodeSelector(5*time.Minute, 15*time.Second)
	server := httptest.NewTLSServer(NewNodeControl(store, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), selector))
	defer server.Close()
	digest := sha256.Sum256(server.Certificate().Raw)
	authority, err := NewRemoteAuthority(RemoteAuthorityConfig{NodeID: "osaka", ControlURL: server.URL, CertificateSHA256: hex.EncodeToString(digest[:]), PrivateKey: nodePrivate})
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Report(NodeStatus{Healthy: true, UploadBPS: 123, DownloadBPS: 456, Devices: 2, Connections: 3, Throttled: 1}); err != nil {
		t.Fatal(err)
	}
	snapshot := selector.Snapshot(time.Now())
	if len(snapshot) != 1 || snapshot[0].ID != "osaka" || snapshot[0].UploadBPS != 123 || snapshot[0].Throttled != 1 {
		t.Fatalf("unexpected report snapshot: %+v", snapshot)
	}
}
