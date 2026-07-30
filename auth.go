package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// deriveMasterKey performs Argon2id key derivation using identical parameters as backend
func deriveMasterKey(password string, saltHex string) ([]byte, error) {
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	// Iterations: 3, Memory: 64MB (65536 KB), Parallelism: 4, Key Length: 32 bytes
	hashBytes := argon2.IDKey([]byte(password), saltBytes, 3, 65536, 4, 32)
	return hashBytes, nil
}

// splitMasterKey derives encKey and clientAuthHash using HKDF-SHA256
func splitMasterKey(masterKey []byte) ([]byte, string, error) {
	// K_enc: Info = "enc_key"
	hkdfEnc := hkdf.New(sha256.New, masterKey, nil, []byte("enc_key"))
	encKey := make([]byte, 32)
	if _, err := hkdfEnc.Read(encKey); err != nil {
		return nil, "", fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// ClientAuthHash: Info = "auth_hash"
	hkdfAuth := hkdf.New(sha256.New, masterKey, nil, []byte("auth_hash"))
	authHashBytes := make([]byte, 32)
	if _, err := hkdfAuth.Read(authHashBytes); err != nil {
		return nil, "", fmt.Errorf("failed to derive client auth hash: %w", err)
	}
	clientAuthHash := hex.EncodeToString(authHashBytes)

	return encKey, clientAuthHash, nil
}

func hexDecode(str string) ([]byte, error) {
	return hex.DecodeString(str)
}
