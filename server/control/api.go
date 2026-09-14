package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Node struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	HostKey  string `json:"host_key"`
}
type signedRequest struct {
	Code      string `json:"code,omitempty"`
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}
type api struct {
	store    *Store
	node     Node
	nodes    map[string]Node
	selector *NodeSelector
	mu       sync.Mutex
	replay   map[[32]byte]int64
	rates    map[string]rate
}
type rate struct {
	Start int64
	Count int
}

func NewAPI(s *Store, node Node) http.Handler {
	return &api{store: s, node: node, replay: map[[32]byte]int64{}, rates: map[string]rate{}}
}

func NewMultiNodeAPI(s *Store, legacy Node, nodes map[string]Node, selector *NodeSelector) http.Handler {
	copyNodes := make(map[string]Node, len(nodes))
	for id, node := range nodes {
		copyNodes[id] = node
	}
	return &api{store: s, node: legacy, nodes: copyNodes, selector: selector, replay: map[[32]byte]int64{}, rates: map[string]rate{}}
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, name string) {
	status := 400
	switch name {
	case "revoked", "invalid_code":
		status = 403
	case "device_limit":
		status = 409
	case "rate_limited":
		status = 429
	case "unavailable":
		status = 503
	}
	reply(w, status, map[string]string{"error": name})
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	return decodeLimit(w, r, out, 8192)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, out any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return false
	}
	var more any
	return d.Decode(&more) == io.EOF
}
func parsePublicKey(s string) (ed25519.PublicKey, bool) {
	const prefix = "ssh-ed25519 "
	if !strings.HasPrefix(s, prefix) {
		return nil, false
	}
	encoded := strings.TrimPrefix(s, prefix)
	b, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil || base64.StdEncoding.EncodeToString(b) != encoded || len(b) != 51 {
		return nil, false
	}
	if binary.BigEndian.Uint32(b[:4]) != 11 || string(b[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(b[15:19]) != 32 {
		return nil, false
	}
	return ed25519.PublicKey(b[19:]), true
}

var codePattern = regexp.MustCompile(`^GBF-[0-9A-F]{32}$`)

func (a *api) allowIP(remote string, now int64) bool {
	ip, _, e := net.SplitHostPort(remote)
	if e != nil {
		ip = remote
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.rates {
		if now-v.Start >= 60 {
			delete(a.rates, k)
		}
	}
	v, ok := a.rates[ip]
	if !ok {
		if len(a.rates) >= 10000 {
			return false
		}
		v = rate{Start: now}
	}
	if v.Count >= 60 {
		return false
	}
	v.Count++
	a.rates[ip] = v
	return true
}
func (a *api) consumeNonce(pub, nonce string, now int64) bool {
	key := sha256.Sum256([]byte(pub + "\n" + nonce))
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, expiry := range a.replay {
		if expiry < now {
			delete(a.replay, k)
		}
	}
	if _, ok := a.replay[key]; ok {
		return false
	}
	if len(a.replay) >= 20000 {
		return false
	}
	a.replay[key] = now + 601
	return true
}
func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isV1 := r.URL.Path == "/v1/activate" || r.URL.Path == "/v1/status"
	isV2 := r.URL.Path == "/v2/activate" || r.URL.Path == "/v2/status"
	isV3 := r.URL.Path == "/v3/activate" || r.URL.Path == "/v3/status"
	if !isV1 && (!(isV2 || isV3) || a.selector == nil) {
		reply(w, 404, map[string]string{"error": "invalid_request"})
		return
	}
	if r.Method != "POST" {
		reply(w, 405, map[string]string{"error": "invalid_request"})
		return
	}
	now := time.Now().Unix()
	if !a.allowIP(r.RemoteAddr, now) {
		fail(w, "rate_limited")
		return
	}
	if isV2 {
		a.serveV2(w, r, now)
		return
	}
	if isV3 {
		a.serveV3(w, r, now)
		return
	}
	var q signedRequest
	if !decode(w, r, &q) {
		fail(w, "invalid_request")
		return
	}
	activate := r.URL.Path == "/v1/activate"
	pub, ok := parsePublicKey(q.PublicKey)
	nonce, e := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	sig, se := base64.StdEncoding.Strict().DecodeString(q.Signature)
	if !ok || e != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce || se != nil || len(sig) != 64 || q.Timestamp < now-300 || q.Timestamp > now+300 || (!activate && q.Code != "") {
		fail(w, "invalid_request")
		return
	}
	if activate && !codePattern.MatchString(q.Code) {
		fail(w, "invalid_code")
		return
	}
	msg := "GBF-STATUS-V1\n" + q.PublicKey + "\n" + strconv.FormatInt(q.Timestamp, 10) + "\n" + q.Nonce
	if activate {
		msg = "GBF-ACTIVATE-V1\n" + q.Code + "\n" + q.PublicKey + "\n" + strconv.FormatInt(q.Timestamp, 10) + "\n" + q.Nonce
	}
	if !ed25519.Verify(pub, []byte(msg), sig) || !a.consumeNonce(q.PublicKey, q.Nonce, now) {
		fail(w, "invalid_request")
		return
	}
	d, count, e := a.store.access(q.Code, q.PublicKey, activate)
	if e != nil {
		fail(w, e.Error())
		return
	}
	reply(w, 200, struct {
		Active      bool   `json:"active"`
		DeviceID    string `json:"device_id"`
		DeviceCount int    `json:"device_count"`
		DeviceLimit int    `json:"device_limit"`
		Node        Node   `json:"node"`
	}{true, d.ID, count, 2, a.node})
}

type clientNodeQuality struct {
	P95MS               int `json:"p95_ms"`
	ConsecutiveTimeouts int `json:"consecutive_timeouts"`
}

type signedRequestV2 struct {
	Code       string                       `json:"code,omitempty"`
	PublicKey  string                       `json:"public_key"`
	Timestamp  int64                        `json:"timestamp"`
	Nonce      string                       `json:"nonce"`
	Signature  string                       `json:"signature"`
	Preference NodePreference               `json:"preference"`
	Quality    map[string]clientNodeQuality `json:"quality"`
}

type publicLine struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

var publicLinesV2 = []publicLine{{"auto", "自动选择"}, {"tokyo", "日本・东京"}, {"osaka", "日本・大阪"}}
var publicLinesV3 = []publicLine{{"auto", "自动选择"}, {"tokyo", "日本・东京"}, {"tokyo_cn2", "日本・东京 CN2"}, {"osaka", "日本・大阪"}}

func v2Message(q signedRequestV2, activate bool) string {
	verb := "STATUS"
	if activate {
		verb = "ACTIVATE"
	}
	tokyo := q.Quality["tokyo"]
	osaka := q.Quality["osaka"]
	return "GBF-" + verb + "-V2\n" + q.Code + "\n" + q.PublicKey + "\n" + strconv.FormatInt(q.Timestamp, 10) + "\n" + q.Nonce + "\n" + string(q.Preference) + "\n" + strconv.Itoa(tokyo.P95MS) + "\n" + strconv.Itoa(tokyo.ConsecutiveTimeouts) + "\n" + strconv.Itoa(osaka.P95MS) + "\n" + strconv.Itoa(osaka.ConsecutiveTimeouts)
}

func validV2Request(q signedRequestV2, activate bool, now int64) (ed25519.PublicKey, bool) {
	pub, ok := parsePublicKey(q.PublicKey)
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	sig, sigErr := base64.StdEncoding.Strict().DecodeString(q.Signature)
	if !ok || nonceErr != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce || sigErr != nil || len(sig) != 64 || q.Timestamp < now-300 || q.Timestamp > now+300 {
		return nil, false
	}
	if q.Preference != PreferenceAuto && q.Preference != PreferenceTokyo && q.Preference != PreferenceOsaka {
		return nil, false
	}
	if len(q.Quality) != 2 {
		return nil, false
	}
	for _, id := range []string{"tokyo", "osaka"} {
		quality, exists := q.Quality[id]
		if !exists || quality.P95MS < 0 || quality.P95MS > 60_000 || quality.ConsecutiveTimeouts < 0 || quality.ConsecutiveTimeouts > 100 {
			return nil, false
		}
	}
	if activate {
		if !codePattern.MatchString(q.Code) {
			return nil, false
		}
	} else if q.Code != "" {
		return nil, false
	}
	if !ed25519.Verify(pub, []byte(v2Message(q, activate)), sig) {
		return nil, false
	}
	return pub, true
}

func v3Message(q signedRequestV2, activate bool) string {
	verb := "STATUS"
	if activate {
		verb = "ACTIVATE"
	}
	message := "GBF-" + verb + "-V3\n" + q.Code + "\n" + q.PublicKey + "\n" + strconv.FormatInt(q.Timestamp, 10) + "\n" + q.Nonce + "\n" + string(q.Preference)
	for _, id := range allNodeIDs {
		quality := q.Quality[id]
		message += "\n" + strconv.Itoa(quality.P95MS) + "\n" + strconv.Itoa(quality.ConsecutiveTimeouts)
	}
	return message
}

func validV3Request(q signedRequestV2, activate bool, now int64) (ed25519.PublicKey, bool) {
	pub, ok := parsePublicKey(q.PublicKey)
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	sig, sigErr := base64.StdEncoding.Strict().DecodeString(q.Signature)
	if !ok || nonceErr != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce || sigErr != nil || len(sig) != 64 || q.Timestamp < now-300 || q.Timestamp > now+300 {
		return nil, false
	}
	if q.Preference != PreferenceAuto && q.Preference != PreferenceTokyo && q.Preference != PreferenceTokyoCN2 && q.Preference != PreferenceOsaka {
		return nil, false
	}
	if len(q.Quality) != len(allNodeIDs) {
		return nil, false
	}
	for _, id := range allNodeIDs {
		quality, exists := q.Quality[id]
		if !exists || quality.P95MS < 0 || quality.P95MS > 60_000 || quality.ConsecutiveTimeouts < 0 || quality.ConsecutiveTimeouts > 100 {
			return nil, false
		}
	}
	if activate {
		if !codePattern.MatchString(q.Code) {
			return nil, false
		}
	} else if q.Code != "" {
		return nil, false
	}
	if !ed25519.Verify(pub, []byte(v3Message(q, activate)), sig) {
		return nil, false
	}
	return pub, true
}

func (a *api) serveV2(w http.ResponseWriter, r *http.Request, now int64) {
	var q signedRequestV2
	if !decode(w, r, &q) {
		fail(w, "invalid_request")
		return
	}
	activate := r.URL.Path == "/v2/activate"
	if _, ok := validV2Request(q, activate, now); !ok || !a.consumeNonce(q.PublicKey, q.Nonce, now) {
		fail(w, "invalid_request")
		return
	}
	d, count, err := a.store.access(q.Code, q.PublicKey, activate)
	if err != nil {
		fail(w, err.Error())
		return
	}
	quality := make(map[string]NodeQuality, 2)
	for id, item := range q.Quality {
		quality[id] = NodeQuality{P95: time.Duration(item.P95MS) * time.Millisecond, ConsecutiveTimeouts: item.ConsecutiveTimeouts}
	}
	selected, err := a.selector.SelectLegacy(d.ID, q.Preference, quality, time.Unix(now, 0))
	if err != nil {
		fail(w, "unavailable")
		return
	}
	node, exists := a.nodes[selected.ID]
	if !exists {
		fail(w, "unavailable")
		return
	}
	label := nodeLabels[selected.ID]
	legacyNodes := map[string]Node{"tokyo": a.nodes["tokyo"], "osaka": a.nodes["osaka"]}
	reply(w, 200, struct {
		Active         bool            `json:"active"`
		DeviceID       string          `json:"device_id"`
		DeviceCount    int             `json:"device_count"`
		DeviceLimit    int             `json:"device_limit"`
		Node           Node            `json:"node"`
		Nodes          map[string]Node `json:"nodes"`
		AssignedLine   publicLine      `json:"assigned_line"`
		AvailableLines []publicLine    `json:"available_lines"`
	}{true, d.ID, count, 2, node, legacyNodes, publicLine{selected.ID, label}, append([]publicLine(nil), publicLinesV2...)})
}

func (a *api) serveV3(w http.ResponseWriter, r *http.Request, now int64) {
	var q signedRequestV2
	if !decode(w, r, &q) {
		fail(w, "invalid_request")
		return
	}
	activate := r.URL.Path == "/v3/activate"
	if _, ok := validV3Request(q, activate, now); !ok || !a.consumeNonce(q.PublicKey, q.Nonce, now) {
		fail(w, "invalid_request")
		return
	}
	d, count, err := a.store.access(q.Code, q.PublicKey, activate)
	if err != nil {
		fail(w, err.Error())
		return
	}
	quality := make(map[string]NodeQuality, len(allNodeIDs))
	for id, item := range q.Quality {
		quality[id] = NodeQuality{P95: time.Duration(item.P95MS) * time.Millisecond, ConsecutiveTimeouts: item.ConsecutiveTimeouts}
	}
	selected, err := a.selector.Select(d.ID, q.Preference, quality, time.Unix(now, 0))
	if err != nil {
		fail(w, "unavailable")
		return
	}
	node, exists := a.nodes[selected.ID]
	if !exists || len(a.nodes) != len(allNodeIDs) {
		fail(w, "unavailable")
		return
	}
	reply(w, 200, struct {
		Active         bool            `json:"active"`
		DeviceID       string          `json:"device_id"`
		DeviceCount    int             `json:"device_count"`
		DeviceLimit    int             `json:"device_limit"`
		Node           Node            `json:"node"`
		Nodes          map[string]Node `json:"nodes"`
		AssignedLine   publicLine      `json:"assigned_line"`
		AvailableLines []publicLine    `json:"available_lines"`
	}{true, d.ID, count, 2, node, a.nodes, publicLine{selected.ID, nodeLabels[selected.ID]}, append([]publicLine(nil), publicLinesV3...)})
}
func NewAdmin(s *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			reply(w, 405, map[string]string{"error": "invalid_request"})
			return
		}
		var q struct {
			ID   string `json:"id"`
			Note string `json:"note"`
		}
		if !decode(w, r, &q) {
			fail(w, "invalid_request")
			return
		}
		if s.Reconcile() != nil {
			fail(w, "unavailable")
			return
		}
		switch r.URL.Path {
		case "/snapshot":
			reply(w, 200, s.Snapshot())
		case "/note-license", "/note-device":
			if e := s.Note(q.ID, q.Note, r.URL.Path == "/note-license"); e != nil {
				fail(w, e.Error())
				return
			}
			reply(w, 200, map[string]bool{"ok": true})
		case "/create":
			if !s.ops.Healthy() {
				fail(w, "unavailable")
				return
			}
			id, code, e := s.Create()
			if e != nil {
				fail(w, "unavailable")
				return
			}
			if s.ops.Event("create", id) != nil {
				fail(w, "unavailable")
				return
			}
			reply(w, 200, map[string]string{"license_id": id, "code": code})
		case "/list":
			reply(w, 200, s.List())
		case "/revoke-device", "/disable-code":
			if !idPattern.MatchString(q.ID) {
				fail(w, "invalid_request")
				return
			}
			var e error
			if r.URL.Path == "/revoke-device" {
				e = s.Revoke(q.ID)
			} else {
				e = s.Disable(q.ID)
			}
			if e != nil {
				fail(w, e.Error())
				return
			}
			if s.ops.Event(strings.TrimPrefix(r.URL.Path, "/"), q.ID) != nil {
				fail(w, "unavailable")
				return
			}
			reply(w, 200, map[string]bool{"ok": true})
		default:
			reply(w, 404, map[string]string{"error": "invalid_request"})
		}
	})
}
