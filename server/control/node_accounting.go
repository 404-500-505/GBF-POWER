package main

import (
	"sort"
	"sync"
	"time"
)

type nodeDeviceCounters struct {
	upload, download                 uint64
	previousUpload, previousDownload uint64
	connections                      int
	sessions                         int
	lastSeen                         int64
	uploadBPS, downloadBPS           uint64
	nextWrite                        [2]time.Time
}

type NodeAccounting struct {
	mu          sync.Mutex
	nodeID      string
	capacityBPS uint64
	limiter     *SustainedLimiter
	devices     map[string]*nodeDeviceCounters
	lastSample  time.Time
	uploadBPS   uint64
	downloadBPS uint64
}

func NewNodeAccounting(nodeID string, capacityBPS uint64, limiter *SustainedLimiter) *NodeAccounting {
	return &NodeAccounting{nodeID: nodeID, capacityBPS: capacityBPS, limiter: limiter, devices: make(map[string]*nodeDeviceCounters)}
}

func (a *NodeAccounting) device(id string) *nodeDeviceCounters {
	device := a.devices[id]
	if device == nil {
		device = &nodeDeviceCounters{}
		a.devices[id] = device
	}
	return device
}

func (a *NodeAccounting) Add(id string, upload bool, n int) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.device(id)
	if upload {
		d.upload += uint64(n)
	} else {
		d.download += uint64(n)
	}
}

func (a *NodeAccounting) Connection(id string, delta int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.device(id)
	d.connections += delta
	if d.connections < 0 {
		d.connections = 0
	}
	if delta > 0 {
		d.lastSeen = time.Now().Unix()
	}
}

func (a *NodeAccounting) Session(id string, delta int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.device(id)
	d.sessions += delta
	if d.sessions < 0 {
		d.sessions = 0
	}
	if delta > 0 {
		d.lastSeen = time.Now().Unix()
	}
}

func (a *NodeAccounting) Sample(now time.Time) {
	a.mu.Lock()
	elapsed := now.Sub(a.lastSample).Seconds()
	var uploadBPS, downloadBPS uint64
	type observation struct {
		id               string
		upload, download uint64
	}
	observations := []observation{}
	if !a.lastSample.IsZero() && elapsed > 0 {
		for id, d := range a.devices {
			upload := uint64(float64(d.upload-d.previousUpload) * 8 / elapsed)
			download := uint64(float64(d.download-d.previousDownload) * 8 / elapsed)
			d.uploadBPS = upload
			d.downloadBPS = download
			uploadBPS += upload
			downloadBPS += download
			observations = append(observations, observation{id, upload, download})
			d.previousUpload = d.upload
			d.previousDownload = d.download
		}
	} else {
		for _, d := range a.devices {
			d.previousUpload = d.upload
			d.previousDownload = d.download
		}
	}
	a.uploadBPS = uploadBPS
	a.downloadBPS = downloadBPS
	a.lastSample = now
	a.mu.Unlock()
	for _, observation := range observations {
		a.limiter.Observe(observation.id, UploadDirection, observation.upload, now)
		a.limiter.Observe(observation.id, DownloadDirection, observation.download, now)
	}
}

func (a *NodeAccounting) Limited(id string, upload bool) bool {
	direction := DownloadDirection
	if upload {
		direction = UploadDirection
	}
	return a.limiter.Limited(id, direction)
}

func (a *NodeAccounting) BeforeWrite(id string, upload bool, n int) {
	if n <= 0 || !a.Limited(id, upload) {
		return
	}
	direction := DownloadDirection
	if upload {
		direction = UploadDirection
	}
	now := time.Now()
	duration := time.Duration(float64(n*8) / float64(a.limiter.LimitBPS()) * float64(time.Second))
	a.mu.Lock()
	device := a.device(id)
	due := device.nextWrite[direction]
	if due.Before(now) {
		due = now
	}
	device.nextWrite[direction] = due.Add(duration)
	a.mu.Unlock()
	if wait := time.Until(due); wait > 0 {
		time.Sleep(wait)
	}
}

func (a *NodeAccounting) Status(now time.Time) NodeStatus {
	a.mu.Lock()
	devices, connections := 0, 0
	activeIDs := make([]string, 0, len(a.devices))
	deviceStates := make([]NodeDeviceStatus, 0, len(a.devices))
	for id, d := range a.devices {
		if d.sessions > 0 || d.connections > 0 {
			activeIDs = append(activeIDs, id)
			devices++
			connections += d.connections
		}
		if d.sessions > 0 || d.connections > 0 || d.uploadBPS > 0 || d.downloadBPS > 0 {
			deviceStates = append(deviceStates, NodeDeviceStatus{ID: id, OnlineSessions: d.sessions, ActiveConnections: d.connections, LastSeen: d.lastSeen, UploadBPS: d.uploadBPS, DownloadBPS: d.downloadBPS})
		}
	}
	sort.Slice(deviceStates, func(i, j int) bool { return deviceStates[i].ID < deviceStates[j].ID })
	peak := a.uploadBPS
	uploadBPS, downloadBPS := a.uploadBPS, a.downloadBPS
	a.mu.Unlock()
	throttled := 0
	for _, id := range activeIDs {
		if a.limiter.Limited(id, UploadDirection) || a.limiter.Limited(id, DownloadDirection) {
			throttled++
		}
	}
	if downloadBPS > peak {
		peak = downloadBPS
	}
	utilization := 0.0
	if a.capacityBPS > 0 {
		utilization = float64(peak) / float64(a.capacityBPS)
		if utilization > 1 {
			utilization = 1
		}
	}
	label := "日本・大阪"
	if a.nodeID == "tokyo" {
		label = "日本・东京"
	}
	return NodeStatus{ID: a.nodeID, Label: label, Healthy: true, UpdatedAt: now, Utilization: utilization, UploadBPS: uploadBPS, DownloadBPS: downloadBPS, Devices: devices, Connections: connections, Throttled: throttled, DeviceStates: deviceStates}
}
