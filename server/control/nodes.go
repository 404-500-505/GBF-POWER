package main

import (
	"errors"
	"sync"
	"time"
)

type NodePreference string

const (
	PreferenceAuto     NodePreference = "auto"
	PreferenceTokyo    NodePreference = "tokyo"
	PreferenceTokyoCN2 NodePreference = "tokyo_cn2"
	PreferenceOsaka    NodePreference = "osaka"
)

var legacyNodeIDs = []string{"tokyo", "osaka"}
var allNodeIDs = []string{"tokyo", "tokyo_cn2", "osaka"}
var nodeLabels = map[string]string{"tokyo": "日本・东京", "tokyo_cn2": "日本・东京 CN2", "osaka": "日本・大阪"}

type NodeStatus struct {
	ID             string             `json:"id"`
	Label          string             `json:"label"`
	Healthy        bool               `json:"healthy"`
	Draining       bool               `json:"draining"`
	UpdatedAt      time.Time          `json:"-"`
	Utilization    float64            `json:"utilization"`
	UploadBPS      uint64             `json:"upload_bps"`
	DownloadBPS    uint64             `json:"download_bps"`
	Devices        int                `json:"devices"`
	Connections    int                `json:"connections"`
	Throttled      int                `json:"throttled_devices"`
	ProbeLatencyMS float64            `json:"probe_latency_ms"`
	ProbeFailures  int                `json:"probe_failures"`
	AuthLatencyMS  float64            `json:"auth_latency_ms"`
	AuthErrors     int                `json:"auth_errors"`
	LastReportAt   int64              `json:"last_report_at"`
	DeviceStates   []NodeDeviceStatus `json:"-"`
}

type NodeDeviceStatus struct {
	ID                string `json:"id"`
	OnlineSessions    int    `json:"online_sessions"`
	ActiveConnections int    `json:"active_connections"`
	LastSeen          int64  `json:"last_seen"`
	UploadBPS         uint64 `json:"upload_bps"`
	DownloadBPS       uint64 `json:"download_bps"`
}

type NodeQuality struct {
	P95                 time.Duration
	ConsecutiveTimeouts int
}

type nodeAssignment struct {
	nodeID string
	at     time.Time
}

type NodeSelector struct {
	mu          sync.Mutex
	nodes       map[string]NodeStatus
	assignments map[string]nodeAssignment
	stickyFor   time.Duration
	staleAfter  time.Duration
	offloading  bool
	lowSince    time.Time
}

var ErrNoHealthyNode = errors.New("no healthy node")

const maxStickyAssignments = 10_000

func NewNodeSelector(stickyFor, staleAfter time.Duration) *NodeSelector {
	return &NodeSelector{
		nodes:       make(map[string]NodeStatus),
		assignments: make(map[string]nodeAssignment),
		stickyFor:   stickyFor,
		staleAfter:  staleAfter,
	}
}

func (s *NodeSelector) Update(status NodeStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[status.ID] = status
	if status.ID != "tokyo" || !status.Healthy {
		return
	}
	if status.Utilization >= 0.70 {
		s.offloading = true
		s.lowSince = time.Time{}
		return
	}
	if !s.offloading {
		return
	}
	if status.Utilization > 0.55 {
		s.lowSince = time.Time{}
		return
	}
	if s.lowSince.IsZero() {
		s.lowSince = status.UpdatedAt
	} else if status.UpdatedAt.Sub(s.lowSince) >= 2*time.Minute {
		s.offloading = false
		s.lowSince = time.Time{}
	}
}

func (s *NodeSelector) eligible(id string, quality map[string]NodeQuality, now time.Time, checkQuality bool) bool {
	n, ok := s.nodes[id]
	if !ok || !n.Healthy || n.Draining || now.Sub(n.UpdatedAt) > s.staleAfter || n.UpdatedAt.After(now.Add(time.Second)) {
		return false
	}
	if checkQuality {
		q := quality[id]
		if q.P95 > 800*time.Millisecond || q.ConsecutiveTimeouts >= 2 {
			return false
		}
	}
	return true
}

func (s *NodeSelector) Select(deviceID string, preference NodePreference, quality map[string]NodeQuality, now time.Time) (NodeStatus, error) {
	return s.selectFrom(deviceID, preference, quality, now, allNodeIDs)
}

func (s *NodeSelector) SelectLegacy(deviceID string, preference NodePreference, quality map[string]NodeQuality, now time.Time) (NodeStatus, error) {
	return s.selectFrom(deviceID, preference, quality, now, legacyNodeIDs)
}

func containsNode(ids []string, wanted string) bool {
	for _, id := range ids {
		if id == wanted {
			return true
		}
	}
	return false
}

func orderedNodes(preference NodePreference, offloading bool, allowed []string) []string {
	order := []string{"tokyo", "tokyo_cn2", "osaka"}
	switch preference {
	case PreferenceTokyoCN2:
		order = []string{"tokyo_cn2", "tokyo", "osaka"}
	case PreferenceOsaka:
		order = []string{"osaka", "tokyo_cn2", "tokyo"}
	case PreferenceAuto:
		if offloading {
			order = []string{"tokyo_cn2", "osaka", "tokyo"}
		}
	}
	result := make([]string, 0, len(allowed))
	for _, id := range order {
		if containsNode(allowed, id) {
			result = append(result, id)
		}
	}
	return result
}

func (s *NodeSelector) selectFrom(deviceID string, preference NodePreference, quality map[string]NodeQuality, now time.Time, allowed []string) (NodeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if preference != PreferenceAuto && preference != PreferenceTokyo && preference != PreferenceTokyoCN2 && preference != PreferenceOsaka {
		preference = PreferenceAuto
	}
	if preference == PreferenceAuto {
		if a, ok := s.assignments[deviceID]; ok && containsNode(allowed, a.nodeID) && now.Sub(a.at) < s.stickyFor && s.eligible(a.nodeID, quality, now, true) {
			return s.nodes[a.nodeID], nil
		}
	}
	checkQuality := preference == PreferenceAuto
	for _, id := range orderedNodes(preference, s.offloading, allowed) {
		if s.eligible(id, quality, now, checkQuality) {
			if _, exists := s.assignments[deviceID]; exists || len(s.assignments) < maxStickyAssignments {
				s.assignments[deviceID] = nodeAssignment{nodeID: id, at: now}
			} else {
				for assignedDevice, assignment := range s.assignments {
					if now.Sub(assignment.at) >= s.stickyFor {
						delete(s.assignments, assignedDevice)
					}
				}
				if len(s.assignments) < maxStickyAssignments {
					s.assignments[deviceID] = nodeAssignment{nodeID: id, at: now}
				}
			}
			return s.nodes[id], nil
		}
	}
	return NodeStatus{}, ErrNoHealthyNode
}

func (s *NodeSelector) Snapshot(now time.Time) []NodeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]NodeStatus, 0, len(allNodeIDs))
	for _, id := range allNodeIDs {
		status, ok := s.nodes[id]
		if !ok {
			continue
		}
		status.LastReportAt = status.UpdatedAt.Unix()
		if now.Sub(status.UpdatedAt) > s.staleAfter {
			status.Healthy = false
		}
		out = append(out, status)
	}
	return out
}
