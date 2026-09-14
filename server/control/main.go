package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	DataDir         string            `json:"data_dir"`
	Listen          string            `json:"listen"`
	TLSCert         string            `json:"tls_cert"`
	TLSKey          string            `json:"tls_key"`
	Node            Node              `json:"node"`
	Nodes           map[string]Node   `json:"nodes,omitempty"`
	NodePublicKeys  map[string]string `json:"node_public_keys,omitempty"`
	MeteringListen  string            `json:"metering_listen"`
	MeteringHostKey string            `json:"metering_host_key"`
	MeteringRules   string            `json:"metering_rules"`
}

func (c Config) Validate() error {
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) || c.TLSCert == "" || c.TLSKey == "" || c.Node.Host == "" || c.Node.Username == "" || c.Node.Port < 1 || c.Node.Port > 65535 {
		return errors.New("invalid config")
	}
	if _, _, e := net.SplitHostPort(c.Listen); e != nil {
		return errors.New("invalid listen address")
	}
	if _, ok := parsePublicKey(c.Node.HostKey); !ok {
		return errors.New("invalid node host key")
	}
	if len(c.Nodes) != 0 || len(c.NodePublicKeys) != 0 {
		if (len(c.Nodes) != 2 && len(c.Nodes) != 3) || len(c.NodePublicKeys) != len(c.Nodes)-1 || c.Nodes["tokyo"] != c.Node {
			return errors.New("invalid multi-node configuration")
		}
		expected := legacyNodeIDs
		if len(c.Nodes) == 3 {
			expected = allNodeIDs
		}
		for _, id := range expected {
			node, ok := c.Nodes[id]
			if !ok || node.Host == "" || node.Username == "" || node.Port < 1 || node.Port > 65535 {
				return errors.New("invalid multi-node configuration")
			}
			if _, ok := parsePublicKey(node.HostKey); !ok {
				return errors.New("invalid multi-node host key")
			}
		}
		for _, id := range expected[1:] {
			if _, ok := parsePublicKey(c.NodePublicKeys[id]); !ok {
				return errors.New("invalid remote node identity key")
			}
		}
	}
	if c.MeteringListen != "" || c.MeteringHostKey != "" || c.MeteringRules != "" {
		if c.MeteringListen == "" || !filepath.IsAbs(c.MeteringHostKey) || !filepath.IsAbs(c.MeteringRules) {
			return errors.New("incomplete metering configuration")
		}
		if _, _, e := net.SplitHostPort(c.MeteringListen); e != nil {
			return errors.New("invalid metering listen address")
		}
	}
	return nil
}
func server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}
func loadConfig(configPath string) (Config, error) {
	b, e := os.ReadFile(configPath)
	if e != nil {
		return Config{}, errors.New("cannot read config")
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return Config{}, errors.New("invalid config JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Config{}, errors.New("invalid config JSON")
	}
	if e = c.Validate(); e != nil {
		return Config{}, e
	}
	return c, nil
}
func serve(configPath string) error {
	c, e := loadConfig(configPath)
	if e != nil {
		return e
	}
	// Bind before opening the DB: an existing daemon owns its state and socket.
	public, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return errors.New("cannot bind public listener")
	}
	defer public.Close()
	adminPath := filepath.Join(c.DataDir, "admin.sock")
	if e = os.MkdirAll(c.DataDir, 0700); e != nil {
		return errors.New("cannot create data directory")
	}
	if info, statErr := os.Lstat(adminPath); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("admin socket path is occupied")
		}
		conn, dialErr := net.DialTimeout("unix", adminPath, time.Second)
		if dialErr == nil {
			conn.Close()
			return errors.New("admin service already running")
		}
		if os.Remove(adminPath) != nil {
			return errors.New("cannot remove stale admin socket")
		}
	} else if !os.IsNotExist(statErr) {
		return errors.New("cannot inspect admin socket")
	}
	admin, e := net.Listen("unix", adminPath)
	if e != nil {
		return errors.New("cannot bind admin socket")
	}
	defer admin.Close()
	defer os.Remove(adminPath)
	if os.Chmod(adminPath, 0600) != nil {
		return errors.New("cannot secure admin socket")
	}
	s, e := OpenStore(c.DataDir)
	if e != nil {
		return errors.New("cannot initialize state and authorized keys")
	}
	publicHandler := NewAPI(s, c.Node)
	var selector *NodeSelector
	var nodeMonitorCancel context.CancelFunc
	var nodeMonitorDone chan struct{}
	if len(c.Nodes) >= 2 {
		selector = NewNodeSelector(5*time.Minute, 15*time.Second)
		s.AttachNodeSelector(selector)
		keys := make(map[string]ed25519.PublicKey, len(c.NodePublicKeys))
		for id, encoded := range c.NodePublicKeys {
			key, _ := parsePublicKey(encoded)
			keys[id] = key
		}
		activationHandler := NewMultiNodeAPI(s, c.Node, c.Nodes, selector)
		controlHandler := NewNodeControl(s, NewNodeRequestVerifier(keys), selector)
		publicHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/internal/") {
				controlHandler.ServeHTTP(w, r)
				return
			}
			activationHandler.ServeHTTP(w, r)
		})
		var nodeMonitorCtx context.Context
		nodeMonitorCtx, nodeMonitorCancel = context.WithCancel(context.Background())
		defer nodeMonitorCancel()
		nodeMonitorDone = make(chan struct{})
		go func() {
			defer close(nodeMonitorDone)
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				selector.Update(localNodeStatus(s, time.Now(), 10_000_000))
				select {
				case <-nodeMonitorCtx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	pubServer := server(publicHandler)
	adminServer := server(NewAdmin(s))
	errs := make(chan error, 3)
	var gateway *Gateway
	if c.MeteringListen != "" {
		rules, err := readRules(c.MeteringRules)
		if err != nil {
			return err
		}
		key, err := os.ReadFile(c.MeteringHostKey)
		if err != nil {
			return errors.New("cannot read metering host key")
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return errors.New("invalid metering host key")
		}
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != c.Node.HostKey {
			return errors.New("metering host key does not match node pin")
		}
		gateway, err = NewGateway(s, c.Node.Username, signer, rules, GatewayNetwork{})
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", c.MeteringListen)
		if err != nil {
			return errors.New("cannot bind metering listener")
		}
		defer gateway.Close()
		go func() { errs <- gateway.Serve(listener) }()
	}
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); runMetering(monitorCtx, s.ops, gateway) }()
	go func() { errs <- adminServer.Serve(admin) }()
	go func() { errs <- pubServer.ServeTLS(public, c.TLSCert, c.TLSKey) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	select {
	case <-stop:
	case <-errs:
		e = errors.New("server stopped unexpectedly")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = pubServer.Shutdown(ctx)
	_ = adminServer.Shutdown(ctx)
	monitorCancel()
	<-monitorDone
	if nodeMonitorCancel != nil {
		nodeMonitorCancel()
		<-nodeMonitorDone
	}
	if gateway != nil {
		_ = gateway.Close()
	}
	if s.ops.Flush() != nil {
		e = errors.New("operations data persistence failed")
	}
	return e
}

func localNodeStatus(s *Store, now time.Time, capacityBPS uint64) NodeStatus {
	o := s.ops
	o.mu.Lock()
	defer o.mu.Unlock()
	var uploadBPS, downloadBPS uint64
	devices, connections := 0, 0
	for _, live := range o.live {
		if live.Online > 0 || live.Active > 0 {
			devices++
		}
		connections += live.Active
		if live.UploadBPS != nil && *live.UploadBPS > 0 {
			uploadBPS += uint64(*live.UploadBPS * 8)
		}
		if live.DownloadBPS != nil && *live.DownloadBPS > 0 {
			downloadBPS += uint64(*live.DownloadBPS * 8)
		}
	}
	utilization := float64(uploadBPS)
	if downloadBPS > uploadBPS {
		utilization = float64(downloadBPS)
	}
	if capacityBPS > 0 {
		utilization /= float64(capacityBPS)
	}
	if utilization > 1 {
		utilization = 1
	}
	return NodeStatus{ID: "tokyo", Label: "日本・东京", Healthy: o.healthy, UpdatedAt: now, Utilization: utilization, UploadBPS: uploadBPS, DownloadBPS: downloadBPS, Devices: devices, Connections: connections}
}
func adminCommand(socket string, args []string) error {
	if len(args) < 1 {
		return errors.New("admin command required")
	}
	path := ""
	q := map[string]string{}
	switch args[0] {
	case "create", "list", "snapshot":
		if len(args) != 1 {
			return errors.New("unexpected command arguments")
		}
		path = "/" + args[0]
	case "revoke-device", "disable-code":
		if len(args) != 2 || !idPattern.MatchString(args[1]) {
			return errors.New("ID required")
		}
		path = "/" + args[0]
		q["id"] = args[1]
	case "note-license", "note-device":
		if len(args) != 3 || !idPattern.MatchString(args[1]) || len(args[2]) > 2668 {
			return errors.New("invalid note arguments")
		}
		note, e := base64.StdEncoding.Strict().DecodeString(args[2])
		if e != nil || base64.StdEncoding.EncodeToString(note) != args[2] || !validNote(string(note)) {
			return errors.New("invalid note encoding or length")
		}
		path = "/" + args[0]
		q["id"] = args[1]
		q["note"] = string(note)
	default:
		return errors.New("unknown admin command")
	}
	b, _ := json.Marshal(q)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	r, e := client.Post("http://localhost"+path, "application/json", bytes.NewReader(b))
	if e != nil {
		return errors.New("cannot reach local admin socket")
	}
	defer r.Body.Close()
	out, e := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if e != nil {
		return errors.New("cannot read admin response")
	}
	if r.StatusCode != 200 {
		return errors.New("admin command rejected")
	}
	_, e = os.Stdout.Write(out)
	return e
}
func run(args []string) error {
	if len(args) > 0 && args[0] == "check-config" {
		f := flag.NewFlagSet("check-config", flag.ContinueOnError)
		config := f.String("config", "", "JSON config file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *config == "" || f.NArg() != 0 {
			return errors.New("usage: gbf-activation check-config --config FILE")
		}
		_, e := loadConfig(*config)
		return e
	}
	if len(args) > 0 && args[0] == "gateway" {
		f := flag.NewFlagSet("gateway", flag.ContinueOnError)
		config := f.String("config", "", "JSON gateway config file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *config == "" || f.NArg() != 0 {
			return errors.New("usage: gbf-activation gateway --config FILE")
		}
		return serveGatewayOnly(*config)
	}
	if len(args) > 0 && args[0] == "authorized-keys" {
		f := flag.NewFlagSet("authorized-keys", flag.ContinueOnError)
		dir := f.String("data-dir", "", "read-only state directory")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *dir == "" || !filepath.IsAbs(*dir) || f.NArg() != 0 {
			return errors.New("usage: gbf-activation authorized-keys --data-dir DIR")
		}
		keys, e := authorizedKeys(*dir)
		if e != nil {
			return errors.New("authorized key lookup unavailable")
		}
		_, e = os.Stdout.Write(keys)
		return e
	}
	if len(args) > 0 && args[0] == "serve" {
		f := flag.NewFlagSet("serve", flag.ContinueOnError)
		config := f.String("config", "", "JSON config file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *config == "" || f.NArg() != 0 {
			return errors.New("usage: gbf-activation serve --config FILE")
		}
		return serve(*config)
	}
	f := flag.NewFlagSet("gbf-activation", flag.ContinueOnError)
	socket := f.String("admin", "", "local Unix admin socket")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *socket == "" {
		return errors.New("usage: gbf-activation --admin SOCKET create|list|revoke-device ID|disable-code ID")
	}
	return adminCommand(*socket, f.Args())
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
