package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type GatewayOnlyConfig struct {
	Listen                   string `json:"listen"`
	Username                 string `json:"username"`
	HostKey                  string `json:"host_key"`
	Rules                    string `json:"rules"`
	NodeID                   string `json:"node_id"`
	ControlURL               string `json:"control_url"`
	ControlCertificateSHA256 string `json:"control_certificate_sha256"`
	NodePrivateKey           string `json:"node_private_key"`
	CapacityBPS              uint64 `json:"capacity_bps"`
}

func (c GatewayOnlyConfig) Validate() error {
	parsed, err := url.Parse(c.ControlURL)
	pin, pinErr := hex.DecodeString(c.ControlCertificateSHA256)
	if _, _, listenErr := net.SplitHostPort(c.Listen); listenErr != nil {
		return errors.New("invalid gateway listen")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`).MatchString(c.Username) || !filepath.IsAbs(c.HostKey) || !filepath.IsAbs(c.Rules) || !filepath.IsAbs(c.NodePrivateKey) || (c.NodeID != "osaka" && c.NodeID != "tokyo_cn2") || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || pinErr != nil || len(pin) != 32 {
		return errors.New("invalid gateway configuration")
	}
	return nil
}

func readGatewayOnlyConfig(path string) (GatewayOnlyConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1<<20 {
		return GatewayOnlyConfig{}, errors.New("cannot read gateway configuration")
	}
	var config GatewayOnlyConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&config) != nil || decoder.Decode(&extra) != io.EOF || config.Validate() != nil {
		return GatewayOnlyConfig{}, errors.New("invalid gateway configuration")
	}
	if config.CapacityBPS == 0 {
		config.CapacityBPS = 1_000_000_000
	}
	return config, nil
}

func readNodeIdentity(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read node identity")
	}
	parsed, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, errors.New("invalid node identity")
	}
	var privateKey ed25519.PrivateKey
	switch key := parsed.(type) {
	case ed25519.PrivateKey:
		privateKey = key
	case *ed25519.PrivateKey:
		privateKey = *key
	default:
		return nil, errors.New("node identity must be Ed25519")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid node identity")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func serveGatewayOnly(configPath string) error {
	config, err := readGatewayOnlyConfig(configPath)
	if err != nil {
		return err
	}
	rules, err := readRules(config.Rules)
	if err != nil {
		return err
	}
	hostRaw, err := os.ReadFile(config.HostKey)
	if err != nil {
		return errors.New("cannot read gateway host key")
	}
	hostSigner, err := ssh.ParsePrivateKey(hostRaw)
	if err != nil {
		return errors.New("invalid gateway host key")
	}
	nodePrivate, err := readNodeIdentity(config.NodePrivateKey)
	if err != nil {
		return err
	}
	authority, err := NewRemoteAuthority(RemoteAuthorityConfig{NodeID: config.NodeID, ControlURL: config.ControlURL, CertificateSHA256: config.ControlCertificateSHA256, PrivateKey: nodePrivate})
	if err != nil {
		return err
	}
	limiter := NewSustainedLimiter(10_000_000, 5_000_000, 30*time.Second, 60*time.Second, 10_000)
	accounting := NewNodeAccounting(config.NodeID, config.CapacityBPS, limiter)
	gateway, err := NewGatewayWithAuthority(authority, accounting, config.Username, hostSigner, rules, GatewayNetwork{})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return errors.New("cannot bind gateway listener")
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- gateway.Serve(listener) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return gateway.Close()
		case <-ticker.C:
			now := time.Now()
			accounting.Sample(now)
			gateway.Recheck()
			status := accounting.Status(now)
			status.Healthy = authority.Healthy()
			_ = authority.Report(status)
		case <-serveResult:
			gateway.Close()
			return errors.New("gateway stopped unexpectedly")
		}
	}
}
