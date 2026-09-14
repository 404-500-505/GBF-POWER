package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func signNodeMessage(t *testing.T, nodeID string, private ed25519.PrivateKey, now time.Time, message func(NodeSignedRequest) string) NodeSignedRequest {
	t.Helper()
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	signed := NodeSignedRequest{NodeID: nodeID, Timestamp: now.Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes)}
	signed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(message(signed))))
	return signed
}

func TestNodeControlAuthorizesActiveDeviceAndFailsClosedAfterRevocation(t *testing.T) {
	s, _, _, code := fixture(t)
	devicePublic, _ := testKey()
	device, _, err := s.access(code, devicePublic, true)
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	control := NewNodeControl(s, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil)

	auth := NodeAuthorizeRequest{PublicKey: devicePublic}
	auth.NodeSignedRequest = signNodeMessage(t, "osaka", nodePrivate, now, func(sig NodeSignedRequest) string { auth.NodeSignedRequest = sig; return auth.SigningMessage() })
	w := request(control, "/internal/v1/authorize", auth)
	requireStatus(t, w, http.StatusOK, "")
	var result NodeAuthorization
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Active || result.DeviceID != device.ID || result.LeaseExpiresAt < now.Unix()+25 || result.LeaseExpiresAt > now.Unix()+35 {
		t.Fatalf("unexpected authorization: %+v", result)
	}
	if err := s.Revoke(device.ID); err != nil {
		t.Fatal(err)
	}
	lease := NodeLeaseRequest{DeviceID: device.ID}
	lease.NodeSignedRequest = signNodeMessage(t, "osaka", nodePrivate, now.Add(time.Second), func(sig NodeSignedRequest) string { lease.NodeSignedRequest = sig; return lease.SigningMessage() })
	requireStatus(t, request(control, "/internal/v1/lease", lease), http.StatusForbidden, "revoked")
}

func TestNodeControlRejectsTamperedAuthorization(t *testing.T) {
	s, _, _, _ := fixture(t)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	control := NewNodeControl(s, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), nil)
	auth := NodeAuthorizeRequest{PublicKey: "original"}
	auth.NodeSignedRequest = signNodeMessage(t, "osaka", nodePrivate, now, func(sig NodeSignedRequest) string { auth.NodeSignedRequest = sig; return auth.SigningMessage() })
	auth.PublicKey = "tampered"
	requireStatus(t, request(control, "/internal/v1/authorize", auth), http.StatusForbidden, "invalid_request")
}

func TestNodeControlReportFeedsAdminSnapshot(t *testing.T) {
	s, _, _, _ := fixture(t)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	selector := NewNodeSelector(5*time.Minute, 15*time.Second)
	control := NewNodeControl(s, NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": nodePublic}), selector)
	report := NodeReportRequest{Status: NodeStatus{Label: "日本・大阪", Healthy: true, Utilization: .25, UploadBPS: 123, DownloadBPS: 456, Devices: 2, Connections: 5, Throttled: 1, ProbeLatencyMS: 61}}
	report.NodeSignedRequest = signNodeMessage(t, "osaka", nodePrivate, now, func(sig NodeSignedRequest) string { report.NodeSignedRequest = sig; return report.SigningMessage() })
	requireStatus(t, request(control, "/internal/v1/report", report), http.StatusOK, "")

	s.AttachNodeSelector(selector)
	w := request(NewAdmin(s), "/snapshot", map[string]string{})
	requireStatus(t, w, http.StatusOK, "")
	if !stringsContainsAll(w.Body.String(), `"id":"osaka"`, `"upload_bps":123`, `"throttled_devices":1`, `"last_report_at":`) {
		t.Fatalf("node report missing from snapshot: %s", w.Body.String())
	}
}

func TestNodeReportSignatureBindsMetrics(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	report := NodeReportRequest{Status: NodeStatus{Healthy: true, UploadBPS: 1}}
	report.NodeSignedRequest = signNodeMessage(t, "osaka", private, now, func(sig NodeSignedRequest) string { report.NodeSignedRequest = sig; return report.SigningMessage() })
	original := report.SigningMessage()
	report.Status.UploadBPS = 2
	if original == report.SigningMessage() {
		t.Fatal("metrics are not bound into signature")
	}
	if fmt.Sprint(report.Status.UploadBPS) != "2" {
		t.Fatal("unexpected test state")
	}
}

func TestNodeReportSignatureBindsPerDeviceState(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	report := NodeReportRequest{
		Status:  NodeStatus{Healthy: true, Devices: 1},
		Devices: []NodeDeviceStatus{{ID: strings.Repeat("a", 24), OnlineSessions: 1, LastSeen: now.Unix()}},
	}
	report.NodeSignedRequest = signNodeMessage(t, "osaka", private, now, func(sig NodeSignedRequest) string {
		report.NodeSignedRequest = sig
		return report.SigningMessage()
	})
	original := report.SigningMessage()
	report.Devices[0].OnlineSessions = 2
	if original == report.SigningMessage() {
		t.Fatal("per-device state is not bound into signature")
	}
}

func stringsContainsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
