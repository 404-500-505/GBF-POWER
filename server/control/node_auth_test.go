package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func signedNodeRequest(t *testing.T, nodeID string, private ed25519.PrivateKey, now time.Time) NodeSignedRequest {
	t.Helper()
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	r := NodeSignedRequest{NodeID: nodeID, Timestamp: now.Unix(), Nonce: base64.RawURLEncoding.EncodeToString(random)}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(r.SigningMessage())))
	return r
}

func TestNodeRequestVerifierAcceptsOnce(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	v := NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": pub})
	r := signedNodeRequest(t, "osaka", private, now)

	if err := v.Verify(r, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := v.Verify(r, now); err != ErrNodeReplay {
		t.Fatalf("replay returned %v, want %v", err, ErrNodeReplay)
	}
}
func TestNodeRequestVerifierRejectsWrongNodeAndStaleTimestamp(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	v := NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": pub})

	r := signedNodeRequest(t, "tokyo", private, now)
	if err := v.Verify(r, now); err != ErrNodeUnknown {
		t.Fatalf("unknown node returned %v", err)
	}
	r = signedNodeRequest(t, "osaka", private, now.Add(-6*time.Minute))
	if err := v.Verify(r, now); err != ErrNodeStale {
		t.Fatalf("stale request returned %v", err)
	}
}

func TestNodeRequestVerifierRejectsTampering(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	v := NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": pub})
	r := signedNodeRequest(t, "osaka", private, now)
	r.Timestamp++

	if err := v.Verify(r, now); err != ErrNodeSignature {
		t.Fatalf("tampered request returned %v", err)
	}
}

func TestNodeRequestVerifierBoundsReplayState(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	v := NewNodeRequestVerifier(map[string]ed25519.PublicKey{"osaka": pub})
	v.MaxReplayEntries = 2
	for i := 0; i < 2; i++ {
		if err := v.Verify(signedNodeRequest(t, "osaka", private, now), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Verify(signedNodeRequest(t, "osaka", private, now), now); err != ErrNodeBusy {
		t.Fatalf("full replay cache returned %v", err)
	}
}
