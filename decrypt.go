package main

import (
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

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
