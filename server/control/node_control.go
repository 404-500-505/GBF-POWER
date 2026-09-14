package main

import (
	"net/http"
	"strconv"
	"time"
)

type NodeAuthorizeRequest struct {
	NodeSignedRequest
	PublicKey string `json:"public_key"`
}

func (r NodeAuthorizeRequest) SigningMessage() string {
	return "GBF-NODE-AUTHORIZE-V1\n" + r.NodeID + "\n" + strconv.FormatInt(r.Timestamp, 10) + "\n" + r.Nonce + "\n" + r.PublicKey
}

type NodeLeaseRequest struct {
	NodeSignedRequest
	DeviceID string `json:"device_id"`
}

func (r NodeLeaseRequest) SigningMessage() string {
	return "GBF-NODE-LEASE-V1\n" + r.NodeID + "\n" + strconv.FormatInt(r.Timestamp, 10) + "\n" + r.Nonce + "\n" + r.DeviceID
}

type NodeReportRequest struct {
	NodeSignedRequest
	Status  NodeStatus         `json:"status"`
	Devices []NodeDeviceStatus `json:"devices"`
}

func (r NodeReportRequest) SigningMessage() string {
	s := r.Status
	message := "GBF-NODE-REPORT-V1\n" + r.NodeID + "\n" + strconv.FormatInt(r.Timestamp, 10) + "\n" + r.Nonce +
		"\n" + strconv.FormatBool(s.Healthy) + "\n" + strconv.FormatBool(s.Draining) + "\n" + strconv.FormatFloat(s.Utilization, 'f', -1, 64) +
		"\n" + strconv.FormatUint(s.UploadBPS, 10) + "\n" + strconv.FormatUint(s.DownloadBPS, 10) + "\n" + strconv.Itoa(s.Devices) +
		"\n" + strconv.Itoa(s.Connections) + "\n" + strconv.Itoa(s.Throttled) + "\n" + strconv.FormatFloat(s.ProbeLatencyMS, 'f', -1, 64) +
		"\n" + strconv.Itoa(s.ProbeFailures) + "\n" + strconv.FormatFloat(s.AuthLatencyMS, 'f', -1, 64) + "\n" + strconv.Itoa(s.AuthErrors)
	if r.Devices == nil {
		return message
	}
	message += "\nGBF-NODE-DEVICES-V1\n" + strconv.Itoa(len(r.Devices))
	for _, device := range r.Devices {
		message += "\n" + device.ID + "\n" + strconv.Itoa(device.OnlineSessions) + "\n" + strconv.Itoa(device.ActiveConnections) +
			"\n" + strconv.FormatInt(device.LastSeen, 10) + "\n" + strconv.FormatUint(device.UploadBPS, 10) + "\n" + strconv.FormatUint(device.DownloadBPS, 10)
	}
	return message
}

type NodeAuthorization struct {
	Active         bool   `json:"active"`
	DeviceID       string `json:"device_id"`
	LicenseID      string `json:"license_id"`
	LeaseExpiresAt int64  `json:"lease_expires_at"`
}

type nodeControl struct {
	store    *Store
	verifier *NodeRequestVerifier
	selector *NodeSelector
}

func NewNodeControl(store *Store, verifier *NodeRequestVerifier, selector *NodeSelector) http.Handler {
	return &nodeControl{store: store, verifier: verifier, selector: selector}
}

func (c *nodeControl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, map[string]string{"error": "invalid_request"})
		return
	}
	now := time.Now()
	switch r.URL.Path {
	case "/internal/v1/authorize":
		var q NodeAuthorizeRequest
		if !decode(w, r, &q) || c.verifier.VerifyMessage(q.NodeSignedRequest, q.SigningMessage(), now) != nil {
			reply(w, http.StatusForbidden, map[string]string{"error": "invalid_request"})
			return
		}
		device, ok := c.store.authenticateKey(q.PublicKey)
		if !ok || !c.store.ops.Healthy() {
			fail(w, "revoked")
			return
		}
		reply(w, http.StatusOK, NodeAuthorization{true, device.ID, device.LicenseID, now.Add(30 * time.Second).Unix()})
	case "/internal/v1/lease":
		var q NodeLeaseRequest
		if !decode(w, r, &q) || !idPattern.MatchString(q.DeviceID) || c.verifier.VerifyMessage(q.NodeSignedRequest, q.SigningMessage(), now) != nil {
			reply(w, http.StatusForbidden, map[string]string{"error": "invalid_request"})
			return
		}
		if !c.store.activeDevice(q.DeviceID) || !c.store.ops.Healthy() {
			fail(w, "revoked")
			return
		}
		reply(w, http.StatusOK, NodeAuthorization{Active: true, DeviceID: q.DeviceID, LeaseExpiresAt: now.Add(30 * time.Second).Unix()})
	case "/internal/v1/report":
		var q NodeReportRequest
		if !decodeLimit(w, r, &q, 64<<10) || c.selector == nil || !validNodeReport(q.Status, q.Devices, now) || c.verifier.VerifyMessage(q.NodeSignedRequest, q.SigningMessage(), now) != nil {
			reply(w, http.StatusForbidden, map[string]string{"error": "invalid_request"})
			return
		}
		q.Status.ID = q.NodeID
		q.Status.Label = nodeLabels[q.NodeID]
		if q.Status.Label == "" {
			reply(w, http.StatusForbidden, map[string]string{"error": "invalid_request"})
			return
		}
		q.Status.UpdatedAt = now
		q.Status.DeviceStates = append([]NodeDeviceStatus(nil), q.Devices...)
		c.selector.Update(q.Status)
		reply(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		reply(w, http.StatusNotFound, map[string]string{"error": "invalid_request"})
	}
}

func validNodeReport(s NodeStatus, devices []NodeDeviceStatus, now time.Time) bool {
	if s.Utilization < 0 || s.Utilization > 1 || s.Devices < 0 || s.Devices > 10_000 || s.Connections < 0 || s.Connections > 100_000 || s.Throttled < 0 || s.Throttled > s.Devices || s.ProbeLatencyMS < 0 || s.ProbeLatencyMS > 60_000 || s.ProbeFailures < 0 || s.AuthLatencyMS < 0 || s.AuthLatencyMS > 60_000 || s.AuthErrors < 0 {
		return false
	}
	if devices == nil {
		return true
	}
	if len(devices) > 64 {
		return false
	}
	seen := map[string]bool{}
	online, connections := 0, 0
	for _, device := range devices {
		if !idPattern.MatchString(device.ID) || seen[device.ID] || device.OnlineSessions < 0 || device.OnlineSessions > 4 || device.ActiveConnections < 0 || device.ActiveConnections > 256 || device.LastSeen < 0 || device.LastSeen > now.Add(5*time.Second).Unix() {
			return false
		}
		seen[device.ID] = true
		if device.OnlineSessions > 0 || device.ActiveConnections > 0 {
			online++
		}
		connections += device.ActiveConnections
	}
	return online == s.Devices && connections == s.Connections
}
