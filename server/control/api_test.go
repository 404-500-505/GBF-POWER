package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKey() (string, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := make([]byte, 51)
	binary.BigEndian.PutUint32(b, 11)
	copy(b[4:], "ssh-ed25519")
	binary.BigEndian.PutUint32(b[15:], 32)
	copy(b[19:], pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b), priv
}
func signed(path, code, pub string, priv ed25519.PrivateKey) map[string]any {
	n := make([]byte, 24)
	rand.Read(n)
	nonce := base64.RawURLEncoding.EncodeToString(n)
	ts := time.Now().Unix()
	msg := fmt.Sprintf("GBF-STATUS-V1\n%s\n%d\n%s", pub, ts, nonce)
	m := map[string]any{"public_key": pub, "timestamp": ts, "nonce": nonce}
	if path == "/v1/activate" {
		msg = fmt.Sprintf("GBF-ACTIVATE-V1\n%s\n%s\n%d\n%s", code, pub, ts, nonce)
		m["code"] = code
	}
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return m
}

func signedV2(path, code, pub string, priv ed25519.PrivateKey, preference string, tokyoP95, tokyoTimeouts, osakaP95, osakaTimeouts int) map[string]any {
	n := make([]byte, 24)
	rand.Read(n)
	nonce := base64.RawURLEncoding.EncodeToString(n)
	ts := time.Now().Unix()
	verb := "STATUS"
	if path == "/v2/activate" {
		verb = "ACTIVATE"
	}
	msg := fmt.Sprintf("GBF-%s-V2\n%s\n%s\n%d\n%s\n%s\n%d\n%d\n%d\n%d", verb, code, pub, ts, nonce, preference, tokyoP95, tokyoTimeouts, osakaP95, osakaTimeouts)
	m := map[string]any{
		"public_key": pub, "timestamp": ts, "nonce": nonce, "preference": preference,
		"quality": map[string]any{
			"tokyo": map[string]int{"p95_ms": tokyoP95, "consecutive_timeouts": tokyoTimeouts},
			"osaka": map[string]int{"p95_ms": osakaP95, "consecutive_timeouts": osakaTimeouts},
		},
	}
	if path == "/v2/activate" {
		m["code"] = code
	}
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return m
}

func signedV3(path, code, pub string, priv ed25519.PrivateKey, preference string, quality map[string][2]int) map[string]any {
	n := make([]byte, 24)
	rand.Read(n)
	nonce := base64.RawURLEncoding.EncodeToString(n)
	ts := time.Now().Unix()
	verb := "STATUS"
	if path == "/v3/activate" {
		verb = "ACTIVATE"
	}
	msg := fmt.Sprintf("GBF-%s-V3\n%s\n%s\n%d\n%s\n%s", verb, code, pub, ts, nonce, preference)
	encoded := map[string]any{}
	for _, id := range []string{"tokyo", "tokyo_cn2", "osaka"} {
		item := quality[id]
		msg += fmt.Sprintf("\n%d\n%d", item[0], item[1])
		encoded[id] = map[string]int{"p95_ms": item[0], "consecutive_timeouts": item[1]}
	}
	m := map[string]any{"public_key": pub, "timestamp": ts, "nonce": nonce, "preference": preference, "quality": encoded}
	if path == "/v3/activate" {
		m["code"] = code
	}
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return m
}
func request(h http.Handler, path string, m any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(m)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func fixture(t *testing.T) (*Store, http.Handler, string, string) {
	t.Helper()
	s, e := OpenStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	id, code, e := s.Create()
	if e != nil {
		t.Fatal(e)
	}
	return s, NewAPI(s, Node{Host: "node", Port: 22, Username: "gbfdevice", HostKey: "pin"}), id, code
}
func requireStatus(t *testing.T, w *httptest.ResponseRecorder, status int, err string) {
	t.Helper()
	if w.Code != status || (err != "" && !strings.Contains(w.Body.String(), `"error":"`+err+`"`)) {
		t.Fatalf("got %d %s want %d %s", w.Code, w.Body.String(), status, err)
	}
}
func TestTwoSlotsAndIdempotency(t *testing.T) {
	_, h, _, code := fixture(t)
	p, k := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	p, k = testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	p, k = testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 409, "device_limit")
}

func TestV1ResponseRemainsLegacyNode(t *testing.T) {
	s, _, _, code := fixture(t)
	legacy := Node{Host: "tokyo.example", Port: 2222, Username: "gbfdevice", HostKey: "legacy-pin"}
	selector := NewNodeSelector(5*time.Minute, 15*time.Second)
	now := time.Now()
	selector.Update(healthyNode("tokyo", 0.10, now))
	selector.Update(healthyNode("osaka", 0.10, now))
	h := NewMultiNodeAPI(s, legacy, map[string]Node{"tokyo": legacy, "osaka": {Host: "osaka.example", Port: 2222, Username: "gbfdevice", HostKey: "osaka-pin"}}, selector)
	pub, priv := testKey()
	w := request(h, "/v1/activate", signed("/v1/activate", code, pub, priv))
	requireStatus(t, w, 200, "")
	if !strings.Contains(w.Body.String(), `"host":"tokyo.example"`) || strings.Contains(w.Body.String(), `osaka.example`) {
		t.Fatalf("legacy response changed: %s", w.Body.String())
	}
}

func TestV2ActivationReturnsSelectedNodeAndSafeLineLabel(t *testing.T) {
	s, e := OpenStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_, code, e := s.Create()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	selector := NewNodeSelector(5*time.Minute, 15*time.Second)
	selector.Update(healthyNode("tokyo", 0.80, now))
	selector.Update(healthyNode("osaka", 0.20, now))
	tokyo := Node{Host: "tokyo.example", Port: 2222, Username: "gbfdevice", HostKey: "tokyo-pin"}
	osaka := Node{Host: "osaka.example", Port: 2222, Username: "gbfdevice", HostKey: "osaka-pin"}
	h := NewMultiNodeAPI(s, tokyo, map[string]Node{"tokyo": tokyo, "osaka": osaka}, selector)
	pub, priv := testKey()
	w := request(h, "/v2/activate", signedV2("/v2/activate", code, pub, priv, "auto", 100, 0, 120, 0))
	requireStatus(t, w, 200, "")
	var got struct {
		Node           Node                         `json:"node"`
		Nodes          map[string]Node              `json:"nodes"`
		AssignedLine   struct{ ID, Label string }   `json:"assigned_line"`
		AvailableLines []struct{ ID, Label string } `json:"available_lines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Node.Host != "osaka.example" || got.Nodes["tokyo"].Host != "tokyo.example" || got.Nodes["osaka"].Host != "osaka.example" || got.AssignedLine.ID != "osaka" || got.AssignedLine.Label != "日本・大阪" {
		t.Fatalf("unexpected v2 assignment: %+v", got)
	}
	if len(got.AvailableLines) != 3 {
		t.Fatalf("got %d available lines", len(got.AvailableLines))
	}
	for _, line := range got.AvailableLines {
		if strings.Contains(line.Label, ".") || strings.Contains(line.Label, ":") || strings.Contains(strings.ToLower(line.Label), "ssh") {
			t.Fatalf("unsafe line label exposed: %q", line.Label)
		}
	}
}

func TestV3ActivationReturnsThreeNodesWhileV2RemainsTwoNodes(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, code, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	selector := NewNodeSelector(5*time.Minute, 15*time.Second)
	selector.Update(healthyNode("tokyo", 0.80, now))
	selector.Update(healthyNode("tokyo_cn2", 0.10, now))
	selector.Update(healthyNode("osaka", 0.20, now))
	tokyo := Node{Host: "tokyo.example", Port: 2222, Username: "gbfdevice", HostKey: "tokyo-pin"}
	nodes := map[string]Node{
		"tokyo":     tokyo,
		"tokyo_cn2": {Host: "cn2.example", Port: 2222, Username: "gbfdevice", HostKey: "cn2-pin"},
		"osaka":     {Host: "osaka.example", Port: 2222, Username: "gbfdevice", HostKey: "osaka-pin"},
	}
	h := NewMultiNodeAPI(s, tokyo, nodes, selector)
	pub, priv := testKey()
	quality := map[string][2]int{"tokyo": {100, 0}, "tokyo_cn2": {80, 0}, "osaka": {120, 0}}
	w := request(h, "/v3/activate", signedV3("/v3/activate", code, pub, priv, "auto", quality))
	requireStatus(t, w, 200, "")
	var v3 struct {
		Node           Node            `json:"node"`
		Nodes          map[string]Node `json:"nodes"`
		AssignedLine   publicLine      `json:"assigned_line"`
		AvailableLines []publicLine    `json:"available_lines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v3); err != nil {
		t.Fatal(err)
	}
	if v3.Node.Host != "cn2.example" || len(v3.Nodes) != 3 || v3.AssignedLine.ID != "tokyo_cn2" || v3.AssignedLine.Label != "日本・东京 CN2" || len(v3.AvailableLines) != 4 {
		t.Fatalf("unexpected v3 response: %+v", v3)
	}

	pub2, priv2 := testKey()
	w = request(h, "/v2/activate", signedV2("/v2/activate", code, pub2, priv2, "auto", 100, 0, 120, 0))
	requireStatus(t, w, 200, "")
	var v2 struct {
		Nodes          map[string]Node `json:"nodes"`
		AvailableLines []publicLine    `json:"available_lines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v2); err != nil {
		t.Fatal(err)
	}
	if len(v2.Nodes) != 2 || v2.Nodes["tokyo_cn2"].Host != "" || len(v2.AvailableLines) != 3 {
		t.Fatalf("v2 compatibility response changed: %+v", v2)
	}
}

func TestV2RejectsUnsignedPreferenceChange(t *testing.T) {
	s, _, _, code := fixture(t)
	now := time.Now()
	selector := NewNodeSelector(5*time.Minute, 15*time.Second)
	selector.Update(healthyNode("tokyo", 0.10, now))
	selector.Update(healthyNode("osaka", 0.10, now))
	h := NewMultiNodeAPI(s, Node{Host: "tokyo", Port: 1}, map[string]Node{"tokyo": {Host: "tokyo", Port: 1}, "osaka": {Host: "osaka", Port: 1}}, selector)
	pub, priv := testKey()
	q := signedV2("/v2/activate", code, pub, priv, "tokyo", 100, 0, 100, 0)
	q["preference"] = "osaka"
	requireStatus(t, request(h, "/v2/activate", q), 400, "invalid_request")
}
func TestConcurrency(t *testing.T) {
	_, h, _, code := fixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, k := testKey()
			w := request(h, "/v1/activate", signed("/v1/activate", code, p, k))
			if w.Code == 200 {
				mu.Lock()
				success++
				mu.Unlock()
			} else if w.Code != 409 {
				t.Errorf("unexpected %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if success != 2 {
		t.Fatalf("got %d successful devices", success)
	}
}
func TestRevocationPersistenceAndGlobalBinding(t *testing.T) {
	s, h, license, code := fixture(t)
	p, k := testKey()
	w := request(h, "/v1/activate", signed("/v1/activate", code, p, k))
	requireStatus(t, w, 200, "")
	var result struct {
		DeviceID string `json:"device_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if e := s.Revoke(result.DeviceID); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 403, "revoked")
	_, other, e := s.Create()
	if e != nil {
		t.Fatal(e)
	}
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", other, p, k)), 403, "revoked")
	p2, k2 := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p2, k2)), 200, "")
	s2, e := OpenStore(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	h2 := NewAPI(s2, Node{})
	requireStatus(t, request(h2, "/v1/status", signed("/v1/status", "", p2, k2)), 200, "")
	if e = s2.Disable(license); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, request(h2, "/v1/status", signed("/v1/status", "", p2, k2)), 403, "revoked")
	b, e := os.ReadFile(filepath.Join(s.dir, "authorized_keys"))
	if e != nil || len(b) != 0 {
		t.Fatalf("keys remain: %v", e)
	}
	b, _ = os.ReadFile(filepath.Join(s.dir, "state.json"))
	if bytes.Contains(b, []byte(code)) || bytes.Contains(b, []byte(other)) {
		t.Fatal("clear code persisted")
	}
}
func TestSignedRequestValidation(t *testing.T) {
	_, h, _, code := fixture(t)
	p, k := testKey()
	m := signed("/v1/activate", code, p, k)
	requireStatus(t, request(h, "/v1/activate", m), 200, "")
	requireStatus(t, request(h, "/v1/activate", m), 400, "invalid_request")
	m = signed("/v1/activate", code, p, k)
	m["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
	requireStatus(t, request(h, "/v1/activate", m), 400, "invalid_request")
	m = signed("/v1/activate", code, p, k)
	m["timestamp"] = time.Now().Unix() - 301
	requireStatus(t, request(h, "/v1/activate", m), 400, "invalid_request")
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", "GBF-"+strings.Repeat("0", 32), p, k)), 403, "invalid_code")
	requireStatus(t, request(h, "/admin/create", map[string]any{}), 404, "invalid_request")
}
func TestExportFailureClosedAndReconcile(t *testing.T) {
	s, h, _, code := fixture(t)
	keys := filepath.Join(s.dir, "authorized_keys")
	if e := os.Remove(keys); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(keys, 0700); e != nil {
		t.Fatal(e)
	}
	p, k := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 503, "unavailable")
	if e := os.Remove(keys); e != nil && !os.IsNotExist(e) {
		t.Fatal(e)
	}
	requireStatus(t, request(h, "/v1/status", signed("/v1/status", "", p, k)), 200, "")
	b, e := os.ReadFile(keys)
	if e != nil || !bytes.Contains(b, []byte(p)) {
		t.Fatal("reconcile failed")
	}
}
func TestAdminSeparateAndListRedacted(t *testing.T) {
	s, h, _, code := fixture(t)
	requireStatus(t, request(h, "/create", map[string]string{}), 404, "invalid_request")
	w := request(NewAdmin(s), "/list", map[string]string{})
	requireStatus(t, w, 200, "")
	if strings.Contains(w.Body.String(), code) || strings.Contains(w.Body.String(), "code_hash") {
		t.Fatal("admin list leaks code material")
	}
	requireStatus(t, request(NewAdmin(s), "/create", map[string]string{}), 200, "")
}
func TestConfigValidation(t *testing.T) {
	if (Config{}).Validate() == nil {
		t.Fatal("empty config accepted")
	}
	p, _ := testKey()
	c := Config{DataDir: t.TempDir(), Listen: ":18444", TLSCert: "cert", TLSKey: "key", Node: Node{Host: "host", Port: 22, Username: "gbfdevice", HostKey: p}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}

func TestServeRejectsMissingListenWithoutBinding(t *testing.T) {
	p, _ := testKey()
	c := Config{
		DataDir: t.TempDir(),
		TLSCert: "cert",
		TLSKey:  "key",
		Node:    Node{Host: "node.example", Port: 22, Username: "gbfdevice", HostKey: p},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := serve(path); err == nil || err.Error() != "invalid listen address" {
		t.Fatalf("missing listen must fail validation before binding, got %v", err)
	}
}

func TestMultiNodeConfigAcceptsPinnedThreeNodeSet(t *testing.T) {
	hostKey, _ := testKey()
	nodeIdentity, _ := testKey()
	tokyo := Node{Host: "tokyo.example", Port: 2222, Username: "gbfdevice", HostKey: hostKey}
	osaka := Node{Host: "osaka.example", Port: 2222, Username: "gbfdevice", HostKey: hostKey}
	c := Config{DataDir: t.TempDir(), Listen: ":18444", TLSCert: "cert", TLSKey: "key", Node: tokyo,
		Nodes: map[string]Node{"tokyo": tokyo, "osaka": osaka}, NodePublicKeys: map[string]string{"osaka": nodeIdentity}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid multi-node config rejected: %v", err)
	}
	delete(c.Nodes, "osaka")
	if err := c.Validate(); err == nil {
		t.Fatal("incomplete node set accepted")
	}
	cn2 := Node{Host: "cn2.example", Port: 2222, Username: "gbfdevice", HostKey: hostKey}
	c.Nodes = map[string]Node{"tokyo": tokyo, "osaka": osaka, "tokyo_cn2": cn2}
	c.NodePublicKeys = map[string]string{"osaka": nodeIdentity, "tokyo_cn2": nodeIdentity}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid three-node config rejected: %v", err)
	}
}
func TestBodyLimitsAndRateLimit(t *testing.T) {
	_, h, _, _ := fixture(t)
	r := httptest.NewRequest("POST", "/v1/activate", strings.NewReader(strings.Repeat("x", 9000)))
	r.RemoteAddr = "192.0.2.2:33"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireStatus(t, w, 400, "invalid_request")
	for i := 0; i < 61; i++ {
		w = request(h, "/v1/activate", map[string]string{})
		if i == 60 {
			requireStatus(t, w, 429, "rate_limited")
		}
	}
}

func TestAuthenticStaleSignatureAndCanonicalKey(t *testing.T) {
	_, h, _, code := fixture(t)
	p, k := testKey()
	m := signed("/v1/activate", code, p, k)
	ts := time.Now().Unix() - 301
	m["timestamp"] = ts
	msg := fmt.Sprintf("GBF-ACTIVATE-V1\n%s\n%s\n%d\n%s", code, p, ts, m["nonce"])
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(k, []byte(msg)))
	requireStatus(t, request(h, "/v1/activate", m), 400, "invalid_request")
	for _, bad := range []string{p + " comment", p + "\n", strings.Replace(p, "ssh-ed25519 ", "ssh-ed25519  ", 1)} {
		requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, bad, k)), 400, "invalid_request")
	}
}

func TestRevocationFreesExactlyOneSlot(t *testing.T) {
	s, h, _, code := fixture(t)
	p, k := testKey()
	w := request(h, "/v1/activate", signed("/v1/activate", code, p, k))
	requireStatus(t, w, 200, "")
	var r struct {
		DeviceID string `json:"device_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &r)
	p2, k2 := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p2, k2)), 200, "")
	if e := s.Revoke(r.DeviceID); e != nil {
		t.Fatal(e)
	}
	p3, k3 := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p3, k3)), 200, "")
	p4, k4 := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p4, k4)), 409, "device_limit")
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 403, "revoked")
}

func TestInvalidSignatureDoesNotConsumeNonce(t *testing.T) {
	_, h, _, code := fixture(t)
	p, k := testKey()
	m := signed("/v1/activate", code, p, k)
	good := m["signature"]
	m["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
	requireStatus(t, request(h, "/v1/activate", m), 400, "invalid_request")
	m["signature"] = good
	requireStatus(t, request(h, "/v1/activate", m), 200, "")
}

func TestServerTransportBounds(t *testing.T) {
	s := server(http.NotFoundHandler())
	if s.TLSConfig.MinVersion < 0x0303 || s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes > 8192 {
		t.Fatal("transport limits missing")
	}
}

func TestRevokedStatusReconcilesFailedExport(t *testing.T) {
	s, h, _, code := fixture(t)
	p, k := testKey()
	w := request(h, "/v1/activate", signed("/v1/activate", code, p, k))
	requireStatus(t, w, 200, "")
	var r struct {
		DeviceID string `json:"device_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &r)
	keys := filepath.Join(s.dir, "authorized_keys")
	if e := os.Remove(keys); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(keys, 0700); e != nil {
		t.Fatal(e)
	}
	if e := s.Revoke(r.DeviceID); e == nil {
		t.Fatal("expected export error")
	}
	requireStatus(t, request(h, "/v1/status", signed("/v1/status", "", p, k)), 403, "revoked")
	b, e := os.ReadFile(keys)
	if e != nil || len(b) != 0 {
		t.Fatalf("revocation export not reconciled: %v", e)
	}
}

func TestAuthorizedKeysLookupUsesCommittedState(t *testing.T) {
	s, h, _, code := fixture(t)
	p, k := testKey()
	w := request(h, "/v1/activate", signed("/v1/activate", code, p, k))
	requireStatus(t, w, 200, "")
	var r struct {
		DeviceID string `json:"device_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &r)
	live, e := authorizedKeys(s.dir)
	if e != nil || !bytes.Contains(live, []byte(p)) {
		t.Fatalf("active lookup failed: %v", e)
	}
	if e = s.Revoke(r.DeviceID); e != nil {
		t.Fatal(e)
	}
	// Simulate an obsolete derived file that could not be replaced after revocation.
	if e = os.WriteFile(filepath.Join(s.dir, "authorized_keys"), live, 0600); e != nil {
		t.Fatal(e)
	}
	got, e := authorizedKeys(s.dir)
	if e != nil || len(got) != 0 {
		t.Fatalf("revoked lookup returned stale key: %v", e)
	}
}

func TestAuthorizedKeysLookupFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if out, e := authorizedKeys(dir); e == nil || len(out) != 0 {
		t.Fatal("missing DB accepted")
	}
	for _, body := range []string{`{`, `null`, `{"licenses":[],"devices":[],"unknown":true}`, `{"licenses":[],"devices":[{"id":"bad","license_id":"missing","public_key":"bad"}]}`} {
		if e := os.WriteFile(filepath.Join(dir, "state.json"), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if out, e := authorizedKeys(dir); e == nil || len(out) != 0 {
			t.Fatalf("bad DB accepted: %s", body)
		}
	}
}

func TestAuthorizedKeysLookupReadOnly(t *testing.T) {
	s, h, _, code := fixture(t)
	p, k := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	dbpath := filepath.Join(s.dir, "state.json")
	before, e := os.ReadFile(dbpath)
	if e != nil {
		t.Fatal(e)
	}
	statBefore, _ := os.Stat(dbpath)
	if e = os.Remove(filepath.Join(s.dir, "authorized_keys")); e != nil {
		t.Fatal(e)
	}
	if _, e = authorizedKeys(s.dir); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(dbpath)
	statAfter, _ := os.Stat(dbpath)
	files, _ := os.ReadDir(s.dir)
	if !bytes.Equal(before, after) || !statBefore.ModTime().Equal(statAfter.ModTime()) || len(files) != 1 || files[0].Name() != "state.json" {
		t.Fatal("lookup modified state or recreated output")
	}
	missing := filepath.Join(s.dir, "missing")
	if _, e = authorizedKeys(missing); e == nil {
		t.Fatal("missing directory accepted")
	}
	if _, e = os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("lookup created missing directory")
	}
}

func TestAuthorizedKeysRejectsMalformedCanonicalKeyAndDisabledCode(t *testing.T) {
	s, h, id, code := fixture(t)
	p, k := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	if e := s.Disable(id); e != nil {
		t.Fatal(e)
	}
	if got, e := authorizedKeys(s.dir); e != nil || len(got) != 0 {
		t.Fatalf("disabled code permitted: %v", e)
	}
	b, e := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	b = bytes.Replace(b, []byte(p), []byte(p+" comment"), 1)
	if e = os.WriteFile(filepath.Join(s.dir, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := authorizedKeys(s.dir); e == nil || len(got) != 0 {
		t.Fatal("malformed persisted key accepted")
	}
}

func TestAuthorizedKeysCLIHelper(t *testing.T) {
	if os.Getenv("GBF_AUTHORIZED_KEYS_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestAuthorizedKeysCLIExitAndStdout(t *testing.T) {
	invoke := func(dir string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAuthorizedKeysCLIHelper$", "--", "authorized-keys", "--data-dir", dir)
		cmd.Env = append(os.Environ(), "GBF_AUTHORIZED_KEYS_HELPER=1")
		out, e := cmd.Output()
		return string(out), e
	}
	missing := t.TempDir()
	if out, e := invoke(missing); e == nil || out != "" {
		t.Fatalf("missing-state CLI must fail with empty stdout: %v", e)
	}
	s, h, _, code := fixture(t)
	p, k := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	dbpath := filepath.Join(s.dir, "state.json")
	before, _ := os.ReadFile(dbpath)
	statBefore, _ := os.Stat(dbpath)
	if e := os.Remove(filepath.Join(s.dir, "authorized_keys")); e != nil {
		t.Fatal(e)
	}
	out, e := invoke(s.dir)
	if e != nil || out != "restrict,port-forwarding "+p+"\n" {
		t.Fatalf("lookup CLI failed: %v", e)
	}
	after, _ := os.ReadFile(dbpath)
	statAfter, _ := os.Stat(dbpath)
	entries, _ := os.ReadDir(s.dir)
	if !bytes.Equal(before, after) || !statBefore.ModTime().Equal(statAfter.ModTime()) || len(entries) != 1 {
		t.Fatal("CLI changed filesystem state")
	}
	if e = os.WriteFile(dbpath, []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	if out, e = invoke(s.dir); e == nil || out != "" {
		t.Fatal("corrupt-state CLI emitted keys or succeeded")
	}
}

func TestOpenStoreRejectsInvalidStateWithoutRewrite(t *testing.T) {
	s, h, _, code := fixture(t)
	p, k := testKey()
	requireStatus(t, request(h, "/v1/activate", signed("/v1/activate", code, p, k)), 200, "")
	dbpath := filepath.Join(s.dir, "state.json")
	valid, e := os.ReadFile(dbpath)
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name, collection, field string
		null                    bool
	}{
		{"missing disabled", "licenses", "disabled", false}, {"null disabled", "licenses", "disabled", true},
		{"missing revoked", "devices", "revoked", false}, {"null revoked", "devices", "revoked", true},
		{"missing licenses", "licenses", "", false}, {"null licenses", "licenses", "", true},
		{"missing devices", "devices", "", false}, {"null devices", "devices", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if e := json.Unmarshal(valid, &value); e != nil {
				t.Fatal(e)
			}
			target := value
			field := tc.collection
			if tc.field != "" {
				target = value[tc.collection].([]any)[0].(map[string]any)
				field = tc.field
			}
			if tc.null {
				target[field] = nil
			} else {
				delete(target, field)
			}
			bad, _ := json.Marshal(value)
			if e := os.WriteFile(dbpath, bad, 0600); e != nil {
				t.Fatal(e)
			}
			before, _ := os.Stat(dbpath)
			keysBefore, _ := os.ReadFile(filepath.Join(s.dir, "authorized_keys"))
			if _, e := OpenStore(s.dir); e == nil {
				t.Error("invalid state accepted at startup")
			}
			after, _ := os.ReadFile(dbpath)
			statAfter, _ := os.Stat(dbpath)
			keysAfter, _ := os.ReadFile(filepath.Join(s.dir, "authorized_keys"))
			if !bytes.Equal(bad, after) || !before.ModTime().Equal(statAfter.ModTime()) || !bytes.Equal(keysBefore, keysAfter) {
				t.Error("startup changed invalid state or exported keys")
			}
		})
	}
}

func TestCommittedRevocationSurvivesDirectorySyncFailure(t *testing.T) {
	s, h, _, code := fixture(t)
	p, k := testKey()
	w := request(h, "/v1/activate", signed("/v1/activate", code, p, k))
	requireStatus(t, w, 200, "")
	var r struct {
		DeviceID string `json:"device_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &r)
	s.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	if e := s.Revoke(r.DeviceID); e == nil {
		t.Fatal("revocation reported success without durable directory entry")
	}
	if !s.db.Devices[0].Revoked {
		t.Fatal("memory reverted committed revocation")
	}
	got, e := authorizedKeys(s.dir)
	if e != nil || len(got) != 0 {
		t.Fatalf("committed DB still authorizes revoked key: %v", e)
	}
	requireStatus(t, request(h, "/v1/status", signed("/v1/status", "", p, k)), 503, "unavailable")
	s.syncDir = func(string) error { return nil }
	requireStatus(t, request(h, "/v1/status", signed("/v1/status", "", p, k)), 403, "revoked")
	_, _, e = s.Create()
	if e != nil {
		t.Fatal(e)
	}
	reloaded, e := OpenStore(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(reloaded.db.Devices) != 1 || !reloaded.db.Devices[0].Revoked {
		t.Fatal("later write resurrected revoked device")
	}
}
