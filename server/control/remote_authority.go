package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type RemoteAuthorityConfig struct {
	NodeID            string
	ControlURL        string
	CertificateSHA256 string
	PrivateKey        ed25519.PrivateKey
}

type remoteLease struct {
	device  Device
	expires time.Time
}

type RemoteAuthority struct {
	mu      sync.Mutex
	config  RemoteAuthorityConfig
	client  *http.Client
	leases  map[string]remoteLease
	healthy bool
	now     func() time.Time
}

func NewRemoteAuthority(config RemoteAuthorityConfig) (*RemoteAuthority, error) {
	parsed, err := url.Parse(config.ControlURL)
	pin, pinErr := hex.DecodeString(config.CertificateSHA256)
	if err != nil || pinErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || len(pin) != sha256.Size || len(config.PrivateKey) != ed25519.PrivateKeySize || (config.NodeID != "tokyo" && config.NodeID != "tokyo_cn2" && config.NodeID != "osaka") {
		return nil, errors.New("invalid remote authority configuration")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 {
			return errors.New("unexpected control certificate chain")
		}
		digest := sha256.Sum256(state.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(digest[:], pin) != 1 {
			return errors.New("control certificate pin mismatch")
		}
		return nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	return &RemoteAuthority{config: config, client: &http.Client{Transport: transport, Timeout: 8 * time.Second}, leases: make(map[string]remoteLease), healthy: true, now: time.Now}, nil
}

func (a *RemoteAuthority) signedRequest() (NodeSignedRequest, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return NodeSignedRequest{}, err
	}
	return NodeSignedRequest{NodeID: a.config.NodeID, Timestamp: a.now().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce)}, nil
}

func (a *RemoteAuthority) sign(request *NodeSignedRequest, message string) {
	request.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.config.PrivateKey, []byte(message)))
}

func (a *RemoteAuthority) post(path string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil || len(body) > 8192 {
		return errors.New("invalid control request")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, a.config.ControlURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	result, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(result.Body, 8193))
	if err != nil || len(raw) > 8192 || result.StatusCode != http.StatusOK {
		return errors.New("control request denied")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(response) != nil {
		return errors.New("invalid control response")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid control response")
	}
	return nil
}
func (a *RemoteAuthority) setHealthy(value bool) {
	a.mu.Lock()
	a.healthy = value
	a.mu.Unlock()
}

func (a *RemoteAuthority) AuthenticateKey(publicKey string) (Device, bool) {
	if _, ok := parsePublicKey(publicKey); !ok {
		return Device{}, false
	}
	signed, err := a.signedRequest()
	if err != nil {
		a.setHealthy(false)
		return Device{}, false
	}
	request := NodeAuthorizeRequest{NodeSignedRequest: signed, PublicKey: publicKey}
	a.sign(&request.NodeSignedRequest, request.SigningMessage())
	var response NodeAuthorization
	if err = a.post("/internal/v1/authorize", request, &response); err != nil || !validNodeAuthorization(response, a.now()) {
		a.setHealthy(false)
		return Device{}, false
	}
	device := Device{ID: response.DeviceID, LicenseID: response.LicenseID, PublicKey: publicKey}
	a.mu.Lock()
	a.leases[device.ID] = remoteLease{device: device, expires: time.Unix(response.LeaseExpiresAt, 0)}
	a.healthy = true
	a.mu.Unlock()
	return device, true
}

func validNodeAuthorization(response NodeAuthorization, now time.Time) bool {
	return response.Active && idPattern.MatchString(response.DeviceID) && idPattern.MatchString(response.LicenseID) && response.LeaseExpiresAt > now.Unix() && response.LeaseExpiresAt <= now.Add(time.Minute).Unix()
}

func (a *RemoteAuthority) ActiveDevice(deviceID string) bool {
	now := a.now()
	a.mu.Lock()
	lease, ok := a.leases[deviceID]
	if ok && now.Before(lease.expires) {
		a.mu.Unlock()
		return true
	}
	a.mu.Unlock()
	if !ok {
		return false
	}
	signed, err := a.signedRequest()
	if err != nil {
		a.setHealthy(false)
		return false
	}
	request := NodeLeaseRequest{NodeSignedRequest: signed, DeviceID: deviceID}
	a.sign(&request.NodeSignedRequest, request.SigningMessage())
	var response NodeAuthorization
	if err = a.post("/internal/v1/lease", request, &response); err != nil || !response.Active || response.DeviceID != deviceID || response.LeaseExpiresAt <= now.Unix() || response.LeaseExpiresAt > now.Add(time.Minute).Unix() {
		a.setHealthy(false)
		return false
	}
	a.mu.Lock()
	lease.expires = time.Unix(response.LeaseExpiresAt, 0)
	a.leases[deviceID] = lease
	a.healthy = true
	a.mu.Unlock()
	return true
}

func (a *RemoteAuthority) Healthy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.healthy
}

func (a *RemoteAuthority) Report(status NodeStatus) error {
	signed, err := a.signedRequest()
	if err != nil {
		a.setHealthy(false)
		return err
	}
	request := NodeReportRequest{NodeSignedRequest: signed, Status: status, Devices: status.DeviceStates}
	a.sign(&request.NodeSignedRequest, request.SigningMessage())
	var response struct {
		OK bool `json:"ok"`
	}
	if err = a.post("/internal/v1/report", request, &response); err != nil || !response.OK {
		a.setHealthy(false)
		if err == nil {
			err = errors.New("node report rejected")
		}
		return err
	}
	a.setHealthy(true)
	return nil
}
