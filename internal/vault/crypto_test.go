package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// makeEncString builds a valid type-2 EncString from raw keys and plaintext.
// Used by tests to produce known-good ciphertexts without going through Login.
func makeEncString(encKey, macKey, plaintext []byte) (string, error) {
	// PKCS7 pad to AES block size
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	mac := h.Sum(nil)

	return fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(mac),
	), nil
}

// mustHex decodes a hex string or panics — only for test fixtures.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// --- pkcs7Unpad ---

func TestPkcs7UnpadValid(t *testing.T) {
	// full-block padding: 16 bytes of data + 16 bytes of 0x10
	fullBlock := make([]byte, 32)
	copy(fullBlock, []byte("0123456789abcdef"))
	for i := 16; i < 32; i++ {
		fullBlock[i] = 0x10
	}

	cases := []struct {
		in   []byte
		want []byte
	}{
		{[]byte{1, 2, 3, 4, 4, 4, 4, 4}, []byte{1, 2, 3, 4}},
		{[]byte{1, 1}, []byte{1}},
		{fullBlock, []byte("0123456789abcdef")},
	}

	for _, c := range cases {
		got, err := pkcs7Unpad(c.in)
		if err != nil {
			t.Errorf("pkcs7Unpad(%v) err=%v", c.in, err)
			continue
		}
		if string(got) != string(c.want) {
			t.Errorf("pkcs7Unpad got %v want %v", got, c.want)
		}
	}
}

func TestPkcs7UnpadInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"zero pad byte", []byte{1, 2, 3, 0}},
		{"pad byte > block size", []byte{1, 2, 3, 17}},
		{"inconsistent bytes", []byte{1, 2, 3, 3, 3, 2}}, // last byte says 2 but [4]=3
	}
	for _, c := range cases {
		if _, err := pkcs7Unpad(c.in); err == nil {
			t.Errorf("pkcs7Unpad(%s): want error, got nil", c.name)
		}
	}
}

// --- decryptEncString ---

func TestDecryptEncStringRoundtrip(t *testing.T) {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("super secret password 123!@#")
	enc, err := makeEncString(encKey, macKey, plaintext)
	if err != nil {
		t.Fatalf("makeEncString: %v", err)
	}

	got, err := decryptEncString(enc, encKey, macKey)
	if err != nil {
		t.Fatalf("decryptEncString: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("got %q want %q", got, plaintext)
	}
}

func TestDecryptEncStringEmpty(t *testing.T) {
	got, err := decryptEncString("", make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("empty string should return nil, got err=%v", err)
	}
	if got != nil {
		t.Errorf("empty string should return nil slice, got %v", got)
	}
}

func TestDecryptEncStringBadMAC(t *testing.T) {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	rand.Read(encKey)
	rand.Read(macKey)

	enc, _ := makeEncString(encKey, macKey, []byte("plaintext"))

	// flip one byte of the MAC (last segment)
	parts := strings.Split(enc, "|")
	macBytes, _ := base64.StdEncoding.DecodeString(parts[2])
	macBytes[0] ^= 0xFF
	parts[2] = base64.StdEncoding.EncodeToString(macBytes)
	tampered := strings.Join(parts, "|")

	if _, err := decryptEncString(tampered, encKey, macKey); err == nil {
		t.Error("expected MAC verification failure, got nil")
	}
}

func TestDecryptEncStringUnsupportedType(t *testing.T) {
	if _, err := decryptEncString("0.abc|def|ghi", make([]byte, 32), make([]byte, 32)); err == nil {
		t.Error("type 0 should be rejected")
	}
	if _, err := decryptEncString("abc|def|ghi", make([]byte, 32), make([]byte, 32)); err == nil {
		t.Error("missing type prefix should be rejected")
	}
}

func TestDecryptEncStringWrongKey(t *testing.T) {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	rand.Read(encKey)
	rand.Read(macKey)

	enc, _ := makeEncString(encKey, macKey, []byte("secret"))

	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	// Wrong mac key → MAC fails
	if _, err := decryptEncString(enc, encKey, wrongKey); err == nil {
		t.Error("wrong mac key should fail MAC check")
	}
}

// --- deriveMasterKey ---

func TestDeriveMasterKeyKnownVector(t *testing.T) {
	// Test vector computed independently with Python:
	//   import hashlib; hashlib.pbkdf2_hmac('sha256', b'password', b'user@example.com', 600000, 32).hex()
	want := mustHex("81be19a9c170df7152970ab88d3bef6de90595ed232b873a876869d68a780d68")
	got, err := deriveMasterKey("password", "User@Example.Com", 600000)
	if err != nil {
		t.Fatalf("deriveMasterKey: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("deriveMasterKey\ngot  %x\nwant %x", got, want)
	}
}

func TestDeriveMasterKeyEmailLowercased(t *testing.T) {
	// Email must be lowercased before use as salt.
	a, _ := deriveMasterKey("password", "User@Example.Com", 1000)
	b, _ := deriveMasterKey("password", "user@example.com", 1000)
	if string(a) != string(b) {
		t.Error("deriveMasterKey should lowercase email before use as salt")
	}
}

func TestDeriveMasterKeyZeroIterations(t *testing.T) {
	if _, err := deriveMasterKey("password", "user@example.com", 0); err == nil {
		t.Error("iterations=0 should return error")
	}
}

// --- stretchMasterKey ---

func TestStretchMasterKeyDeterministic(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)

	a, err := stretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := stretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if a.enc != b.enc || a.mac != b.mac {
		t.Error("stretchMasterKey is not deterministic for the same input")
	}
}

func TestStretchMasterKeyEncMacDiffer(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)

	sk, err := stretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if sk.enc == sk.mac {
		t.Error("enc and mac keys must differ")
	}
}

func TestStretchThenDecryptRoundtrip(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	sk, _ := stretchMasterKey(mk)

	plaintext := []byte("vault item name")
	enc, err := makeEncString(sk.enc[:], sk.mac[:], plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptEncString(enc, sk.enc[:], sk.mac[:])
	if err != nil {
		t.Fatalf("decrypt after stretch: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("got %q want %q", got, plaintext)
	}
}
