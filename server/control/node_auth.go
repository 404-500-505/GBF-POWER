package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"sync"
	"time"
)

var (
	ErrNodeUnknown   = errors.New("unknown node")
	ErrNodeStale     = errors.New("stale node request")
	ErrNodeSignature = errors.New("invalid node signature")
	ErrNodeReplay    = errors.New("replayed node request")
	ErrNodeBusy      = errors.New("node verifier busy")
)

type NodeSignedRequest struct {
	NodeID    string `json:"node_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

func (r NodeSignedRequest) SigningMessage() string {
	return "GBF-NODE-V1\n" + r.NodeID + "\n" + strconv.FormatInt(r.Timestamp, 10) + "\n" + r.Nonce
}

type NodeRequestVerifier struct {
	mu               sync.Mutex
	keys             map[string]ed25519.PublicKey
	replay           map[string]int64
	MaxReplayEntries int
}

func NewNodeRequestVerifier(keys map[string]ed25519.PublicKey) *NodeRequestVerifier {
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		copyKeys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &NodeRequestVerifier{keys: copyKeys, replay: make(map[string]int64), MaxReplayEntries: 20_000}
}

func (v *NodeRequestVerifier) Verify(r NodeSignedRequest, now time.Time) error {
	return v.VerifyMessage(r, r.SigningMessage(), now)
}

func (v *NodeRequestVerifier) VerifyMessage(r NodeSignedRequest, message string, now time.Time) error {
	key, ok := v.keys[r.NodeID]
	if !ok {
		return ErrNodeUnknown
	}
	if r.Timestamp < now.Unix()-300 || r.Timestamp > now.Unix()+300 {
		return ErrNodeStale
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(r.Nonce)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != r.Nonce {
		return ErrNodeSignature
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(r.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != r.Signature || !ed25519.Verify(key, []byte(message), signature) {
		return ErrNodeSignature
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for nonce, expiry := range v.replay {
		if expiry < now.Unix() {
			delete(v.replay, nonce)
		}
	}
	replayKey := r.NodeID + "\n" + r.Nonce
	if _, exists := v.replay[replayKey]; exists {
		return ErrNodeReplay
	}
	if len(v.replay) >= v.MaxReplayEntries {
		return ErrNodeBusy
	}
	v.replay[replayKey] = now.Unix() + 601
	return nil
}
