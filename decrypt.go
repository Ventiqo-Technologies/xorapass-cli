package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func ioReadFull(b []byte) (int, error) {
	return io.ReadFull(rand.Reader, b)
}

// EncryptedPayload representation of our database schema for vault entries
type EncryptedPayload struct {
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

// decryptPayload decrypts the cipher using XChaCha20-Poly1305 with the key
func decryptPayload(payload EncryptedPayload, nonceStr string, encKey []byte) (string, error) {
	// Recreate cipher instance
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize xchacha20poly1305: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return "", errors.New("invalid base64 nonce or length")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return "", errors.New("invalid base64 ciphertext")
	}

	tag, err := base64.StdEncoding.DecodeString(payload.Tag)
	if err != nil {
		return "", errors.New("invalid base64 authentication tag")
	}

	// Recombine ciphertext and tag
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	opened, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("failed to open envelope: authentication mismatch or corrupt payload: %w", err)
	}

	return string(opened), nil
}

// encryptPayload encrypts the plaintext using XChaCha20-Poly1305 with the key
func encryptPayload(plaintext string, encKey []byte) (EncryptedPayload, string, error) {
	var payload EncryptedPayload
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return payload, "", fmt.Errorf("failed to initialize xchacha20poly1305: %w", err)
	}

	// Generate standard random 24-byte nonce for XChaCha20
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := ioReadFull(nonce); err != nil {
		return payload, "", fmt.Errorf("failed to generate secure nonce: %w", err)
	}

	// Seal the envelope
	sealed := aead.Seal(nil, nonce, []byte(plaintext), nil)

	// Split into ciphertext and tag (standard Poly1305 tag is trailing 16 bytes)
	tagSize := 16
	if len(sealed) < tagSize {
		return payload, "", errors.New("sealed payload is too short")
	}
	
	ciphertextBytes := sealed[:len(sealed)-tagSize]
	tagBytes := sealed[len(sealed)-tagSize:]

	payload.Ciphertext = base64.StdEncoding.EncodeToString(ciphertextBytes)
	payload.Tag = base64.StdEncoding.EncodeToString(tagBytes)
	nonceStr := base64.StdEncoding.EncodeToString(nonce)

	return payload, nonceStr, nil
}
