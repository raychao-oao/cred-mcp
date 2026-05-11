package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// stretchedKey holds the 64-byte stretched master key (encKey || macKey).
type stretchedKey struct {
	enc [32]byte
	mac [32]byte
}

// deriveMasterKey runs PBKDF2-SHA256 on password+email with the given iteration
// count. The result is the 32-byte master key used for all further derivation.
func deriveMasterKey(password, email string, iterations int) ([]byte, error) {
	if iterations <= 0 {
		return nil, fmt.Errorf("kdf iterations must be > 0")
	}
	return pbkdf2.Key([]byte(password), []byte(strings.ToLower(email)), iterations, 32, sha256.New), nil
}

// masterKeyHash returns the value sent to the server during login:
// PBKDF2-SHA256(masterKey, password, 1).
func masterKeyHash(masterKey []byte, password string) []byte {
	return pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
}

// stretchMasterKey derives the enc+mac key pair from the 32-byte master key
// using HKDF-SHA256 expand.
func stretchMasterKey(masterKey []byte) (stretchedKey, error) {
	var sk stretchedKey
	r := hkdf.Expand(sha256.New, masterKey, []byte("enc"))
	if _, err := io.ReadFull(r, sk.enc[:]); err != nil {
		return sk, err
	}
	r = hkdf.Expand(sha256.New, masterKey, []byte("mac"))
	if _, err := io.ReadFull(r, sk.mac[:]); err != nil {
		return sk, err
	}
	return sk, nil
}

// decryptEncString decrypts a Bitwarden EncString using the provided enc+mac keys.
// Supported format: "2.<iv_b64>|<ct_b64>|<mac_b64>" (AES-256-CBC + HMAC-SHA256).
func decryptEncString(encStr string, encKey, macKey []byte) ([]byte, error) {
	if encStr == "" {
		return nil, nil
	}

	dot := strings.IndexByte(encStr, '.')
	if dot < 0 {
		return nil, fmt.Errorf("malformed enc string: missing type prefix")
	}
	typeStr := encStr[:dot]
	rest := encStr[dot+1:]

	encType, err := strconv.Atoi(typeStr)
	if err != nil || encType != 2 {
		return nil, fmt.Errorf("unsupported enc type %q (only type 2 supported)", typeStr)
	}

	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed enc string: expected 3 parts, got %d", len(parts))
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid iv: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid mac: %w", err)
	}

	// Verify MAC: HMAC-SHA256(macKey, iv || ct)
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	// Decrypt AES-256-CBC
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length not a multiple of block size")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)

	// Remove PKCS7 padding
	plain, err = pkcs7Unpad(plain)
	if err != nil {
		return nil, fmt.Errorf("unpad: %w", err)
	}
	return plain, nil
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(b) {
		return nil, fmt.Errorf("invalid padding byte %d", pad)
	}
	if !bytes.Equal(b[len(b)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, fmt.Errorf("padding bytes inconsistent")
	}
	return b[:len(b)-pad], nil
}
