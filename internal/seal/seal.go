package seal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"time"

	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

// Seal encrypts plaintext against the session public key in bundle using HPKE
// (DHKEM-X25519 + HKDF-SHA256 + ChaCha20Poly1305). The HPKE info parameter
// binds the ciphertext to (consumerID, sessionID, itemID, purpose, expiries,
// boxID) preventing replay across different requests.
//
// Callers are responsible for: verifying the bundle (credproto.VerifyBundle),
// checking registry ACLs, and validating the auth token before calling Seal.
func Seal(bundle *credproto.ConsumerBundle, itemID, purpose, boxID string, boxExpiresAt time.Time, plaintext []byte) (*credproto.SealedBox, error) {
	info := credproto.MarshalInfo(
		bundle.ConsumerID, bundle.SessionID,
		itemID, purpose,
		bundle.ExpiresAt, boxExpiresAt, boxID,
	)

	ecdhPub, err := ecdh.X25519().NewPublicKey(bundle.SessionPubKey)
	if err != nil {
		return nil, err
	}
	pub, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		return nil, err
	}

	enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, err
	}

	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, err
	}

	return &credproto.SealedBox{
		BoxID:       boxID,
		ConsumerID:  bundle.ConsumerID,
		SessionID:   bundle.SessionID,
		ItemID:      itemID,
		Purpose:     purpose,
		EncappedKey: enc,
		Ciphertext:  ct,
		ExpiresAt:   boxExpiresAt,
	}, nil
}

// zeroize overwrites b with zeros to limit plaintext lifetime in memory.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SealAndZeroize calls Seal and then zeroizes the plaintext slice.
func SealAndZeroize(bundle *credproto.ConsumerBundle, itemID, purpose, boxID string, boxExpiresAt time.Time, plaintext []byte) (*credproto.SealedBox, error) {
	box, err := Seal(bundle, itemID, purpose, boxID, boxExpiresAt, plaintext)
	zeroize(plaintext)
	return box, err
}

