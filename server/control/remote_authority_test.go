package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func remoteAuthorityFixture(t *testing.T, handler http.Handler, nodePrivate ed25519.PrivateKey) (*RemoteAuthority, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.StartTLS()
	digest := sha256.Sum256(server.Certificate().Raw)
	authority, err := NewRemoteAuthority(RemoteAuthorityConfig{NodeID: "osaka", ControlURL: server.URL, CertificateSHA256: hex.EncodeToString(digest[:]), PrivateKey: nodePrivate})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return authority, server
}

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

func TestRemoteAuthorityCollapsesConcurrentAuthorizationForOneKey(t *testing.T) {
	store, _, _, code := fixture(t)
	devicePublic, _ := testKey()
	device, _, err := store.access(code, devicePublic, true)
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	control := NewNodeControl(store, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil)
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/v1/authorize" {
			requests.Add(1)
			time.Sleep(50 * time.Millisecond)
		}
		control.ServeHTTP(w, r)
	})
	authority, server := remoteAuthorityFixture(t, handler, nodePrivate)
	defer server.Close()

	const clients = 4
	var wg sync.WaitGroup
	wg.Add(clients)
	results := make(chan Device, clients)
	for range clients {
		go func() {
			defer wg.Done()
			if got, ok := authority.AuthenticateKey(devicePublic); ok {
				results <- got
			}
		}()
	}
	wg.Wait()
	close(results)
	if len(results) != clients {
		t.Fatalf("authorized %d/%d concurrent clients", len(results), clients)
	}
	for got := range results {
		if got.ID != device.ID || got.LicenseID != device.LicenseID {
			t.Fatalf("unexpected cached authorization: %+v", got)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("control authorization requests=%d, want 1", got)
	}
}

func TestRemoteAuthorityReusesTLSConnectionAcrossDifferentKeys(t *testing.T) {
	store, _, _, code := fixture(t)
	firstPublic, _ := testKey()
	secondPublic, _ := testKey()
	if _, _, err := store.access(code, firstPublic, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.access(code, secondPublic, true); err != nil {
		t.Fatal(err)
	}
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	control := NewNodeControl(store, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil)
	server := httptest.NewUnstartedServer(control)
	var connections atomic.Int32
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	digest := sha256.Sum256(server.Certificate().Raw)
	authority, err := NewRemoteAuthority(RemoteAuthorityConfig{NodeID: "osaka", ControlURL: server.URL, CertificateSHA256: hex.EncodeToString(digest[:]), PrivateKey: nodePrivate})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := authority.AuthenticateKey(firstPublic); !ok {
		t.Fatal("first key authorization failed")
	}
	if _, ok := authority.AuthenticateKey(secondPublic); !ok {
		t.Fatal("second key authorization failed")
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("TLS connections=%d, want 1 reused connection", got)
	}
}

func TestRemoteAuthorityAuthorizationCacheExpiresBeforeDeviceLease(t *testing.T) {
	store, _, _, code := fixture(t)
	devicePublic, _ := testKey()
	device, _, err := store.access(code, devicePublic, true)
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	control := NewNodeControl(store, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil)
	authority, server := remoteAuthorityFixture(t, control, nodePrivate)
	defer server.Close()
	now := time.Now()
	authority.now = func() time.Time { return now }
	if _, ok := authority.AuthenticateKey(devicePublic); !ok {
		t.Fatal("initial authorization failed")
	}
	if err := store.Revoke(device.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := authority.AuthenticateKey(devicePublic); !ok {
		t.Fatal("short startup cache was not honored")
	}
	now = now.Add(6 * time.Second)
	if _, ok := authority.AuthenticateKey(devicePublic); ok {
		t.Fatal("revoked device survived the short authorization cache")
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
