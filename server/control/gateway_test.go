package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fixedResolver struct{ addresses []net.IPAddr }

type fakeGatewayAuthority struct {
	mu      sync.RWMutex
	device  Device
	active  bool
	healthy bool
}

func (a *fakeGatewayAuthority) AuthenticateKey(string) (Device, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.device, a.active && a.healthy
}
func (a *fakeGatewayAuthority) ActiveDevice(string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.active && a.healthy
}
func (a *fakeGatewayAuthority) Healthy() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
func (a *fakeGatewayAuthority) setActive(active bool) {
	a.mu.Lock()
	a.active = active
	a.mu.Unlock()
}

type fakeGatewayAccounting struct{}

func (fakeGatewayAccounting) Add(string, bool, int)  {}
func (fakeGatewayAccounting) Connection(string, int) {}
func (fakeGatewayAccounting) Session(string, int)    {}

func publicFixtureIP() string {
	// Build a routable test address without embedding a deployable endpoint in
	// the public source tree; no connection is made to this address.
	return net.IPv4(93, 184, 216, 34).String()
}

func TestRulesAllowOnlyConfiguredNonstandardHostPort(t *testing.T) {
	rules := Rules{
		DomainSuffixes: []string{"granbluefantasy.jp"},
		ExactHostPorts: []ExactHostPort{{Host: "ws.game.granbluefantasy.jp", Port: 11240}, {Host: "198.51.100.14", Port: 11240}},
	}
	for _, target := range []struct {
		host string
		port uint32
	}{{"WS.GAME.GRANBLUEFANTASY.JP.", 11240}, {"198.51.100.14", 11240}, {"game.granbluefantasy.jp", 443}} {
		if !rules.Allows(target.host, target.port) {
			t.Fatalf("configured target rejected: %s:%d", target.host, target.port)
		}
	}
	for _, target := range []struct {
		host string
		port uint32
	}{{"game.granbluefantasy.jp", 11240}, {"ws.game.granbluefantasy.jp", 11241}, {"ws.game.granbluefantasy.jp.evil.test", 11240}, {"example.com", 11240}} {
		if rules.Allows(target.host, target.port) {
			t.Fatalf("unconfigured target allowed: %s:%d", target.host, target.port)
		}
	}
}

func TestReadRulesValidatesExactHostPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	valid := `{"exact_host_ports":[{"host":"ws.game.granbluefantasy.jp","port":11240}]}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := readRules(path)
	if err != nil || !rules.Allows("ws.game.granbluefantasy.jp", 11240) {
		t.Fatalf("valid exact host/port rules rejected: %v", err)
	}
	for _, invalid := range []string{
		`{"exact_host_ports":[{"host":"ws.game.granbluefantasy.jp.evil.test/","port":11240}]}`,
		`{"exact_host_ports":[{"host":"ws.game.granbluefantasy.jp","port":0}]}`,
		`{"exact_host_ports":[{"host":"ws.game.granbluefantasy.jp","port":65536}]}`,
	} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRules(path); err == nil {
			t.Fatalf("invalid exact host/port rules accepted: %s", invalid)
		}
	}
}

func (r fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses, nil
}

type echoDialer struct {
	address string
	mu      sync.Mutex
	targets []string
}

func (d *echoDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, target)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

type gatewayFixture struct {
	store   *Store
	gateway *Gateway
	client  *ssh.Client
	device  Device
	license string
	signer  ssh.Signer
	address string
	dialer  *echoDialer
	hostKey string
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	s, _, lid, code := fixture(t)
	pub, priv := testKey()
	dev, _, e := s.access(code, pub, true)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, e := ssh.NewSignerFromKey(hostPriv)
	if e != nil {
		t.Fatal(e)
	}
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	dialer := &echoDialer{address: echo.Addr().String()}
	fixtureIP := publicFixtureIP()
	g, e := NewGateway(s, "gbfdevice", hostSigner, Rules{DomainSuffixes: []string{"granbluefantasy.jp"}, ExactHosts: []string{fixtureIP}}, GatewayNetwork{Resolver: fixedResolver{[]net.IPAddr{{IP: net.ParseIP(fixtureIP)}}}, Dialer: dialer})
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- g.Serve(listener) }()
	t.Cleanup(func() {
		g.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("gateway did not stop")
		}
	})
	client, e := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "gbfdevice", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()), Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	return &gatewayFixture{s, g, client, dev, lid, signer, listener.Addr().String(), dialer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))}
}
func transfer(t *testing.T, client *ssh.Client, payload string) net.Conn {
	t.Helper()
	c, e := client.Dial("tcp", "game.granbluefantasy.jp:443")
	if e != nil {
		t.Fatal(e)
	}
	// SSH channel conns do not implement deadlines, so bound the whole exchange.
	done := make(chan error, 1)
	go func() {
		_, e := io.WriteString(c, payload)
		if e == nil {
			b := make([]byte, len(payload))
			_, e = io.ReadFull(c, b)
			if e == nil && string(b) != payload {
				e = errors.New("echo mismatch")
			}
		}
		done <- e
	}()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		c.Close()
		t.Fatal("transfer timeout")
	}
	return c
}
func waitDevice(t *testing.T, s *Store, id string, check func(OpsDevice) bool) OpsDevice {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range s.Snapshot().Licenses {
			for _, d := range l.Devices {
				if d.ID == id && check(d) {
					return d
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("device condition not reached")
	return OpsDevice{}
}
func TestSSHCountsSuccessfulPayloadAndPersists(t *testing.T) {
	f := newGatewayFixture(t)
	payload := strings.Repeat("encrypted-payload", 4096)
	c := transfer(t, f.client, payload)
	d := waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool { return d.Upload == uint64(len(payload)) && d.Download == uint64(len(payload)) })
	if d.Active != 1 || d.LastSeen == 0 || d.TodayUpload != d.Upload || d.TodayDownload != d.Download {
		t.Fatalf("bad active snapshot: %+v", d)
	}
	f.dialer.mu.Lock()
	targets := append([]string{}, f.dialer.targets...)
	f.dialer.mu.Unlock()
	if len(targets) != 1 || targets[0] != net.JoinHostPort(publicFixtureIP(), "443") {
		t.Fatalf("dial did not pin validated IP: %v", targets)
	}
	c.Close()
	waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool { return d.Active == 0 })
	if e := f.store.ops.Flush(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(f.store.dir)
	if e != nil {
		t.Fatal(e)
	}
	waitDevice(t, reopened, f.device.ID, func(d OpsDevice) bool {
		return d.Upload == uint64(len(payload)) && d.Download == uint64(len(payload)) && d.Active == 0
	})
}

func TestSSHClientHalfClosePreservesResponse(t *testing.T) {
	f := newGatewayFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	f.dialer.address = listener.Addr().String()
	upload := strings.Repeat("request-body", 1024)
	download := strings.Repeat("response-after-request-eof", 4096)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil && string(request) != upload {
			err = errors.New("request truncated")
		}
		if err == nil {
			_, err = io.WriteString(conn, download)
		}
		serverDone <- err
	}()
	conn, err := f.client.Dial("tcp", "game.granbluefantasy.jp:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clientDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(conn, upload)
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		if err == nil {
			response, readErr := io.ReadAll(conn)
			err = readErr
			if err == nil && string(response) != download {
				err = errors.New("response truncated after client CloseWrite")
			}
		}
		clientDone <- err
	}()
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("half-close response timed out")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool {
		return d.Active == 0 && d.Upload == uint64(len(upload)) && d.Download == uint64(len(download))
	})
}

func TestSSHTargetHalfClosePreservesClientUpload(t *testing.T) {
	f := newGatewayFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	f.dialer.address = listener.Addr().String()
	upload := strings.Repeat("upload-after-server-eof", 1024)
	download := "server-greeting"
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = io.WriteString(conn, download)
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		if err == nil {
			request, readErr := io.ReadAll(conn)
			err = readErr
			if err == nil && string(request) != upload {
				err = errors.New("upload truncated after target CloseWrite")
			}
		}
		serverDone <- err
	}()
	conn, err := f.client.Dial("tcp", "game.granbluefantasy.jp:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clientDone := make(chan error, 1)
	go func() {
		greeting, err := io.ReadAll(conn)
		if err == nil && string(greeting) != download {
			err = errors.New("greeting truncated")
		}
		if err == nil {
			_, err = io.WriteString(conn, upload)
		}
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		clientDone <- err
	}()
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("half-close upload timed out")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool {
		return d.Active == 0 && d.Upload == uint64(len(upload)) && d.Download == uint64(len(download))
	})
}
func TestSSHRejectsOtherUsesAndRevokesLiveConnection(t *testing.T) {
	f := newGatewayFixture(t)
	if session, e := f.client.NewSession(); e == nil {
		session.Close()
		t.Fatal("session allowed")
	}
	if l, e := f.client.Listen("tcp", "127.0.0.1:0"); e == nil {
		l.Close()
		t.Fatal("remote forwarding allowed")
	}
	if _, _, e := f.client.SendRequest("keepalive@"+"openssh.com", true, nil); e != nil {
		t.Fatal("keepalive disconnected", e)
	}
	for _, target := range []string{"evilgranbluefantasy.jp:443", "granbluefantasy.jp.evil.test:443", "game.granbluefantasy.jp:22", "127.0.0.1:443", "10.0.0.1:80"} {
		if c, e := f.client.Dial("tcp", target); e == nil {
			c.Close()
			t.Fatalf("allowed %s", target)
		}
	}
	c := transfer(t, f.client, "before-revoke")
	if e := f.store.Revoke(f.device.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { b := make([]byte, 1); _, e := c.Read(b); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("live socket survived revoke")
		}
	case <-time.After(time.Second):
		t.Fatal("revoke did not immediately close")
	}
	waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool { return d.Active == 0 })
	if c, e := ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: "gbfdevice", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second}); e == nil {
		c.Close()
		t.Fatal("revoked key authenticated")
	}
}
func TestSSHUserAndDeviceConnectionLimit(t *testing.T) {
	f := newGatewayFixture(t)
	config := &ssh.ClientConfig{User: "wrong", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second}
	if c, e := ssh.Dial("tcp", f.address, config); e == nil {
		c.Close()
		t.Fatal("wrong username allowed")
	}
	config.User = "gbfdevice"
	for i := 0; i < 3; i++ {
		c, e := ssh.Dial("tcp", f.address, config)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		cc := transfer(t, c, "ok")
		cc.Close()
	}
	c, e := ssh.Dial("tcp", f.address, config)
	if e == nil {
		defer c.Close()
		if channel, e := c.Dial("tcp", "game.granbluefantasy.jp:443"); e == nil {
			channel.Close()
			t.Fatal("fifth device SSH connection allowed")
		}
	}
}
func TestGatewayRejectsNonPublicResolvedAddresses(t *testing.T) {
	f := newGatewayFixture(t)
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "100.64.0.1", "169.254.169.254", "192.0.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:" + "127.0.0.1", "2001:db8::1", "64:ff9b:" + ":7f00:1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Errorf("nonpublic IP accepted: %s", ip)
		}
	}
	publicIPv6 := strings.Join([]string{"2606", "4700", "4700", "", "1111"}, ":")
	if !publicIP(net.ParseIP(publicFixtureIP())) || !publicIP(net.ParseIP(publicIPv6)) {
		t.Fatal("public address rejected")
	}
	_ = f
}

func TestGatewayCanUseRemoteAuthorityWithoutLocalStateDatabase(t *testing.T) {
	_, devicePrivate := testKey()
	deviceSigner, err := ssh.NewSignerFromKey(devicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority := &fakeGatewayAuthority{device: Device{ID: "aaaaaaaaaaaaaaaaaaaaaaaa", LicenseID: "bbbbbbbbbbbbbbbbbbbbbbbb"}, active: true, healthy: true}
	rules := Rules{DomainSuffixes: []string{"granbluefantasy.jp"}}
	gateway, err := NewGatewayWithAuthority(authority, fakeGatewayAccounting{}, "gbfdevice", hostSigner, rules, GatewayNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- gateway.Serve(listener) }()
	defer func() { gateway.Close(); <-done }()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "gbfdevice", Auth: []ssh.AuthMethod{ssh.PublicKeys(deviceSigner)}, HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	authority.setActive(false)
	gateway.Recheck()
	if channel, err := client.Dial("tcp", "game.granbluefantasy.jp:443"); err == nil {
		channel.Close()
		t.Fatal("inactive remote lease still opened a channel")
	}
}
func TestOperationsFailureIsClosedAndNotOverwritten(t *testing.T) {
	f := newGatewayFixture(t)
	path := filepath.Join(f.store.dir, "ops.json")
	f.store.ops.syncDir = func(string) error { return errors.New("disk error") }
	if f.store.ops.Flush() == nil {
		t.Fatal("flush failure hidden")
	}
	if f.store.Snapshot().Metering.Healthy {
		t.Fatal("health falsely healthy")
	}
	if c, e := f.client.Dial("tcp", "game.granbluefantasy.jp:443"); e == nil {
		c.Close()
		t.Fatal("forward opened with unhealthy accounting")
	}
	if e := os.WriteFile(path, []byte("{invalid"), 0600); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(f.store.dir)
	if e != nil {
		t.Fatal(e)
	}
	if reopened.ops.Healthy() {
		t.Fatal("corrupt ops accepted")
	}
	if reopened.ops.Flush() == nil {
		t.Fatal("corrupt ops silently replaced")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "{invalid" {
		t.Fatal("corrupt ops overwritten")
	}
}

func TestSSHDevicesRemainAttributedAndDisableIsScoped(t *testing.T) {
	f := newGatewayFixture(t)
	_, code, e := f.store.Create()
	if e != nil {
		t.Fatal(e)
	}
	pub, priv := testKey()
	second, _, e := f.store.access(code, pub, true)
	if e != nil {
		t.Fatal(e)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	client, e := ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: "gbfdevice", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	c1 := transfer(t, f.client, strings.Repeat("a", 137))
	defer c1.Close()
	c2 := transfer(t, client, strings.Repeat("b", 593))
	defer c2.Close()
	waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool { return d.Upload == 137 && d.Download == 137 })
	waitDevice(t, f.store, second.ID, func(d OpsDevice) bool { return d.Upload == 593 && d.Download == 593 })
	if e := f.store.Disable(f.license); e != nil {
		t.Fatal(e)
	}
	waitDevice(t, f.store, f.device.ID, func(d OpsDevice) bool { return d.Active == 0 })
	c3 := transfer(t, client, "still-active")
	c3.Close()
}

func TestSSHChannelLimitAndDNSMixedAnswers(t *testing.T) {
	f := newGatewayFixture(t)
	channels := []net.Conn{}
	defer func() {
		for _, c := range channels {
			c.Close()
		}
	}()
	for i := 0; i < 64; i++ {
		c, e := f.client.Dial("tcp", "game.granbluefantasy.jp:443")
		if e != nil {
			t.Fatal("allowed channel rejected", i, e)
		}
		channels = append(channels, c)
	}
	if c, e := f.client.Dial("tcp", "game.granbluefantasy.jp:443"); e == nil {
		c.Close()
		t.Fatal("65th channel allowed")
	}
	f.gateway.network.Resolver = fixedResolver{[]net.IPAddr{{IP: net.ParseIP(publicFixtureIP())}, {IP: net.ParseIP("10.0.0.1")}}}
	if c, e := f.gateway.dial(context.Background(), "game.granbluefantasy.jp", 443); e == nil {
		c.Close()
		t.Fatal("mixed private/public DNS accepted")
	}
}

func TestGlobalConnectionBudgetIncludesForwardedSockets(t *testing.T) {
	f := newGatewayFixture(t)
	// Consume the remaining capacity without creating hundreds of OS sockets.
	for i := 0; i < 255; i++ {
		f.gateway.slots <- struct{}{}
	}
	defer func() {
		for i := 0; i < 255; i++ {
			<-f.gateway.slots
		}
	}()
	if c, e := f.client.Dial("tcp", "game.granbluefantasy.jp:443"); e == nil {
		c.Close()
		t.Fatal("forwarded socket exceeded global connection budget")
	}
}

func TestGatewayShutdownClosesIdleHandshake(t *testing.T) {
	f := newGatewayFixture(t)
	raw, e := net.Dial("tcp", f.address)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	// Read the identification line, proving that the handshake worker started.
	raw.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 256)
	if _, e := raw.Read(b); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { f.gateway.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown leaked handshake worker")
	}
}
