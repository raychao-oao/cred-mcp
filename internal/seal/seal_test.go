package seal_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"testing"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/seal"
	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

// makeTestBundle creates a signed ConsumerBundle with a freshly generated
// X25519 session keypair. Returns the bundle and the private session key
// (needed to open the SealedBox in tests).
func makeTestBundle(t *testing.T) (*credproto.ConsumerBundle, *ecdh.PrivateKey) {
	t.Helper()

	identPub, identPriv, _ := ed25519.GenerateKey(rand.Reader)
	sessionPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sessionPub := sessionPriv.PublicKey()

	b := &credproto.ConsumerBundle{
		ConsumerID:     "pty-mcp",
		SessionID:      "sess-test",
		SessionPubKey:  sessionPub.Bytes(),
		IdentityPubKey: []byte(identPub),
		ExpiresAt:      time.Now().Add(time.Hour).UTC(),
	}
	b.Signature = ed25519.Sign(identPriv, credproto.MarshalBundleBytes(b))
	return b, sessionPriv
}

func TestSeal_RoundTrip(t *testing.T) {
	bundle, sessionPriv := makeTestBundle(t)
	boxExp := time.Now().Add(5 * time.Minute).UTC()
	plaintext := []byte("hunter2")

	box, err := seal.Seal(bundle, "item-42", "ssh-login", "box-xyz", boxExp, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Verify metadata
	if box.BoxID != "box-xyz" || box.ConsumerID != "pty-mcp" ||
		box.SessionID != "sess-test" || box.ItemID != "item-42" ||
		box.Purpose != "ssh-login" {
		t.Fatalf("unexpected SealedBox metadata: %+v", box)
	}
	if len(box.EncappedKey) == 0 || len(box.Ciphertext) == 0 {
		t.Fatal("SealedBox has empty EncappedKey or Ciphertext")
	}

	// Open using raw HPKE to verify round-trip
	info := credproto.MarshalInfo(
		bundle.ConsumerID, bundle.SessionID,
		"item-42", "ssh-login",
		bundle.ExpiresAt, boxExp, "box-xyz",
	)
	hpkePriv, err := hpke.NewDHKEMPrivateKey(sessionPriv)
	if err != nil {
		t.Fatalf("NewDHKEMPrivateKey: %v", err)
	}
	recipient, err := hpke.NewRecipient(box.EncappedKey, hpkePriv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	got, err := recipient.Open(nil, box.Ciphertext)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestSeal_DifferentBoxIDProducesUndecryptable(t *testing.T) {
	bundle, sessionPriv := makeTestBundle(t)
	boxExp := time.Now().Add(5 * time.Minute).UTC()

	box, _ := seal.Seal(bundle, "item-42", "ssh-login", "box-real", boxExp, []byte("secret"))

	// Try to open with wrong boxID in info — info mismatch → HPKE decryption fails
	info := credproto.MarshalInfo(
		bundle.ConsumerID, bundle.SessionID,
		"item-42", "ssh-login",
		bundle.ExpiresAt, boxExp, "box-WRONG",
	)
	hpkePriv, _ := hpke.NewDHKEMPrivateKey(sessionPriv)
	recipient, _ := hpke.NewRecipient(box.EncappedKey, hpkePriv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	_, err := recipient.Open(nil, box.Ciphertext)
	if err == nil {
		t.Fatal("expected Open to fail with wrong boxID, but it succeeded")
	}
}
