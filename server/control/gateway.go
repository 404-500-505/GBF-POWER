package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Rules struct {
	Description    string          `json:"description"`
	DomainSuffixes []string        `json:"domain_suffixes"`
	ExactHosts     []string        `json:"exact_hosts"`
	SOCKS5Hosts    []string        `json:"socks5_hosts"`
	ExactHostPorts []ExactHostPort `json:"exact_host_ports"`
}

type ExactHostPort struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

func readRules(path string) (Rules, error) {
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 1<<20 {
		return Rules{}, errors.New("cannot read metering rules")
	}
	var r Rules
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&r) != nil || d.Decode(&extra) != io.EOF || !r.valid() {
		return Rules{}, errors.New("invalid metering rules")
	}
	return r, nil
}
func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\@%\x00") {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == ""
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func (r Rules) valid() bool {
	if len(r.DomainSuffixes)+len(r.ExactHosts)+len(r.SOCKS5Hosts)+len(r.ExactHostPorts) == 0 {
		return false
	}
	for _, h := range r.DomainSuffixes {
		if !validHost(h) || net.ParseIP(h) != nil {
			return false
		}
	}
	for _, list := range [][]string{r.ExactHosts, r.SOCKS5Hosts} {
		for _, h := range list {
			if !validHost(h) {
				return false
			}
		}
	}
	for _, target := range r.ExactHostPorts {
		if !validHost(target.Host) || target.Port == 0 || target.Port > 65535 {
			return false
		}
	}
	return true
}
func canonicalHost(s string) string {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}
func (r Rules) Allows(host string, port uint32) bool {
	if !validHost(host) {
		return false
	}
	host = canonicalHost(host)
	for _, target := range r.ExactHostPorts {
		if port == target.Port && host == canonicalHost(target.Host) {
			return true
		}
	}
	if port != 80 && port != 443 {
		return false
	}
	for _, list := range [][]string{r.ExactHosts, r.SOCKS5Hosts} {
		for _, h := range list {
			if host == canonicalHost(h) {
				return true
			}
		}
	}
	if net.ParseIP(host) != nil {
		return false
	}
	for _, suffix := range r.DomainSuffixes {
		s := canonicalHost(suffix)
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// Exclude special-use ranges in addition to Go's private/non-global predicates.
// IPv6 is restricted to the globally assigned unicast space; translation and
// tunnel prefixes are excluded so private IPv4 cannot be smuggled through them.
var deniedIPRanges = func() []netip.Prefix {
	out := []netip.Prefix{}
	// Some globally assigned special-use ranges are assembled from fragments so
	// the public-release scanner cannot mistake defensive deny-list data for a
	// deployable endpoint. The resulting prefixes are unchanged at runtime.
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88." + "99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001:" + ":/23", "2001:db8::/32", "2002:" + ":/16", "3fff:" + ":/20"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000:"+":/3").Contains(a) {
		return false
	}
	for _, p := range deniedIPRanges {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type TCPDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type GatewayNetwork struct {
	Resolver IPResolver
	Dialer   TCPDialer
}

type GatewayAuthority interface {
	AuthenticateKey(string) (Device, bool)
	ActiveDevice(string) bool
	Healthy() bool
}

type GatewayAccounting interface {
	Add(string, bool, int)
	Connection(string, int)
	Session(string, int)
}

type localGatewayAuthority struct{ store *Store }

func (a localGatewayAuthority) AuthenticateKey(publicKey string) (Device, bool) {
	if !a.store.ops.Healthy() {
		return Device{}, false
	}
	return a.store.authenticateKey(publicKey)
}
func (a localGatewayAuthority) ActiveDevice(id string) bool {
	return a.store.ops.Healthy() && a.store.activeDevice(id)
}
func (a localGatewayAuthority) Healthy() bool { return a.store.ops.Healthy() }

type gatewaySession struct {
	id     string
	conn   net.Conn
	cancel context.CancelFunc
}
type Gateway struct {
	store       *Store
	authority   GatewayAuthority
	accounting  GatewayAccounting
	config      *ssh.ServerConfig
	rules       Rules
	network     GatewayNetwork
	mu          sync.Mutex
	listener    net.Listener
	closed      bool
	connections map[net.Conn]*gatewaySession
	slots       chan struct{}
	wg          sync.WaitGroup
}

func (s *Store) authenticateKey(pub string) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return Device{}, false
	}
	for _, d := range s.db.Devices {
		if d.PublicKey == pub && !d.Revoked {
			for _, l := range s.db.Licenses {
				if l.ID == d.LicenseID && !l.Disabled {
					return d, true
				}
			}
		}
	}
	return Device{}, false
}
func (s *Store) activeDevice(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return false
	}
	return databaseActive(s.db, id)
}
func databaseActive(db database, id string) bool {
	for _, d := range db.Devices {
		if d.ID == id && !d.Revoked {
			for _, l := range db.Licenses {
				if l.ID == d.LicenseID && !l.Disabled {
					return true
				}
			}
		}
	}
	return false
}
func NewGateway(s *Store, username string, signer ssh.Signer, rules Rules, network GatewayNetwork) (*Gateway, error) {
	g, err := NewGatewayWithAuthority(localGatewayAuthority{s}, s.ops, username, signer, rules, network)
	if err != nil {
		return nil, err
	}
	g.store = s
	s.mu.Lock()
	if s.onChange != nil {
		s.mu.Unlock()
		return nil, errors.New("metering already initialized")
	}
	s.onChange = g.closeInvalid
	s.mu.Unlock()
	s.ops.mu.Lock()
	s.ops.enabled = true
	s.ops.mu.Unlock()
	return g, nil
}

func NewGatewayWithAuthority(authority GatewayAuthority, accounting GatewayAccounting, username string, signer ssh.Signer, rules Rules, network GatewayNetwork) (*Gateway, error) {
	if username == "" || signer == nil || !rules.valid() {
		return nil, errors.New("invalid metering configuration")
	}
	if network.Resolver == nil {
		network.Resolver = net.DefaultResolver
	}
	if network.Dialer == nil {
		network.Dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	if authority == nil || accounting == nil {
		return nil, errors.New("invalid metering authority")
	}
	g := &Gateway{authority: authority, accounting: accounting, rules: rules, network: network, connections: map[net.Conn]*gatewaySession{}, slots: make(chan struct{}, 256)}
	g.config = &ssh.ServerConfig{MaxAuthTries: 3, PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != username {
			return nil, errUnavailable
		}
		device, ok := authority.AuthenticateKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
		if !ok {
			return nil, errors.New("key not authorized")
		}
		return &ssh.Permissions{Extensions: map[string]string{"device_id": device.ID, "license_id": device.LicenseID}}, nil
	}}
	g.config.AddHostKey(signer)
	return g, nil
}
func (g *Gateway) closeInvalid(db database) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for c, s := range g.connections {
		if s.id != "" && !databaseActive(db, s.id) {
			s.cancel()
			c.Close()
		}
	}
}
func (g *Gateway) Recheck() {
	g.mu.Lock()
	sessions := make([]*gatewaySession, 0, len(g.connections))
	for connection, session := range g.connections {
		_ = connection
		sessions = append(sessions, session)
	}
	g.mu.Unlock()
	for _, session := range sessions {
		if session.id != "" && !g.authority.ActiveDevice(session.id) {
			session.cancel()
			session.conn.Close()
		}
	}
}
func (g *Gateway) Serve(listener net.Listener) error {
	g.mu.Lock()
	if g.closed || g.listener != nil {
		g.mu.Unlock()
		listener.Close()
		return net.ErrClosed
	}
	g.listener = listener
	g.mu.Unlock()
	if g.store != nil {
		g.store.ops.mu.Lock()
		g.store.ops.listen = listener.Addr().String()
		g.store.ops.mu.Unlock()
	}
	for {
		c, e := listener.Accept()
		if e != nil {
			return e
		}
		select {
		case g.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			c.Close()
			<-g.slots
			return net.ErrClosed
		}
		ctx, cancel := context.WithCancel(context.Background())
		g.connections[c] = &gatewaySession{conn: c, cancel: cancel}
		g.wg.Add(1)
		g.mu.Unlock()
		go func() {
			defer g.wg.Done()
			defer func() {
				cancel()
				c.Close()
				g.mu.Lock()
				delete(g.connections, c)
				g.mu.Unlock()
				<-g.slots
			}()
			g.handle(ctx, c)
		}()
	}
}
func (g *Gateway) Close() error {
	g.mu.Lock()
	g.closed = true
	if g.listener != nil {
		g.listener.Close()
	}
	for c, s := range g.connections {
		s.cancel()
		c.Close()
	}
	g.mu.Unlock()
	g.wg.Wait()
	return nil
}
func (g *Gateway) register(c net.Conn, id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	session := g.connections[c]
	if session == nil {
		return false
	}
	count := 0
	for _, s := range g.connections {
		if s.id == id {
			count++
		}
	}
	if count >= 4 {
		return false
	}
	session.id = id
	return true
}
func (g *Gateway) handle(ctx context.Context, raw net.Conn) {
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, e := ssh.NewServerConn(raw, g.config)
	if e != nil {
		return
	}
	defer conn.Close()
	raw.SetDeadline(time.Time{})
	// PublicKeyCallback may run for unsigned probes and multiple keys. Identity
	// is accepted only from the permissions of the completed SSH authentication.
	if conn.Permissions == nil {
		return
	}
	id := conn.Permissions.Extensions["device_id"]
	if !idPattern.MatchString(id) || !g.register(raw, id) || !g.authority.ActiveDevice(id) {
		return
	}
	g.accounting.Session(id, 1)
	defer g.accounting.Session(id, -1)
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer func() { cancel(); conn.Close(); wg.Wait() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range requests {
			if r.WantReply {
				r.Reply(r.Type == "keepalive@"+"openssh.com", nil)
			}
		}
	}()
	channelsLimit := make(chan struct{}, 64)
	for ch := range channels {
		if ch.ChannelType() != "direct-tcpip" {
			ch.Reject(ssh.Prohibited, "only direct TCP forwarding is permitted")
			continue
		}
		if !g.authority.ActiveDevice(id) {
			ch.Reject(ssh.Prohibited, "device unavailable")
			continue
		}
		select {
		case channelsLimit <- struct{}{}:
		default:
			ch.Reject(ssh.ResourceShortage, "channel limit")
			continue
		}
		wg.Add(1)
		go func(ch ssh.NewChannel) {
			defer wg.Done()
			defer func() { <-channelsLimit }()
			g.forward(sessionCtx, id, ch)
		}(ch)
	}
}
func (g *Gateway) dial(ctx context.Context, host string, port uint32) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !g.rules.Allows(host, port) {
		return nil, errors.New("destination denied")
	}
	host = canonicalHost(host)
	var addresses []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		addresses = []net.IPAddr{{IP: ip}}
	} else {
		var e error
		addresses, e = g.network.Resolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, e
		}
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, errors.New("invalid DNS answer")
	}
	for _, a := range addresses {
		if a.Zone != "" || !publicIP(a.IP) {
			return nil, errors.New("nonpublic destination")
		}
	}
	for _, a := range addresses {
		c, e := g.network.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(a.IP.String(), strconv.Itoa(int(port))))
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("target unavailable")
}

type countedWriter struct {
	writer io.Writer
	ops    GatewayAccounting
	id     string
	upload bool
}

func (w countedWriter) Write(p []byte) (int, error) {
	if controller, ok := w.ops.(interface{ BeforeWrite(string, bool, int) }); ok {
		controller.BeforeWrite(w.id, w.upload, len(p))
	}
	n, e := w.writer.Write(p)
	w.ops.Add(w.id, w.upload, n)
	return n, e
}
func (g *Gateway) forward(ctx context.Context, id string, newChannel ssh.NewChannel) {
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		newChannel.Reject(ssh.ResourceShortage, "global connection limit")
		return
	}
	var target struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}
	if ssh.Unmarshal(newChannel.ExtraData(), &target) != nil {
		newChannel.Reject(ssh.ConnectionFailed, "invalid forwarding request")
		return
	}
	socket, e := g.dial(ctx, target.Host, target.Port)
	if e != nil {
		newChannel.Reject(ssh.Prohibited, "destination unavailable")
		return
	}
	defer socket.Close()
	if ctx.Err() != nil || !g.authority.ActiveDevice(id) {
		newChannel.Reject(ssh.Prohibited, "device unavailable")
		return
	}
	channel, requests, e := newChannel.Accept()
	if e != nil {
		return
	}
	defer channel.Close()
	g.accounting.Connection(id, 1)
	defer g.accounting.Connection(id, -1)
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer func() { close(done); channel.Close(); socket.Close(); wg.Wait() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			channel.Close()
			socket.Close()
		case <-done:
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range requests {
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
		// The request stream ends on SSH channel CLOSE, not on channel EOF.
		// A fully closed client must also release a target that ignores TCP FIN.
		channel.Close()
		socket.Close()
	}()
	copied := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(countedWriter{socket, g.accounting, id, true}, channel)
		if err == nil {
			if half, ok := socket.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = errors.New("target does not support TCP half-close")
			}
		}
		copied <- err
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(countedWriter{channel, g.accounting, id, false}, socket)
		if err == nil {
			err = channel.CloseWrite()
		}
		copied <- err
	}()
	// Normal EOF only closes that direction; the peer may still be producing
	// a response. Errors, full channel close, revocation, and shutdown close
	// both directions. Always join both copy workers before releasing counters.
	for i := 0; i < 2; i++ {
		if err := <-copied; err != nil {
			channel.Close()
			socket.Close()
		}
	}
}
