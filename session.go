package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

type ConfigSession struct {
	Email          string `json:"email"`
	AccessToken    string `json:"access_token"`
	EncryptionKey  string `json:"encryption_key"` // base64 encoded encKey
}

func getSessionFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(homeDir, ".xora")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(configDir, "session.json"), nil
}

func saveSession(email, token string, encKey []byte) error {
	path, err := getSessionFilePath()
	if err != nil {
		return err
	}

	session := ConfigSession{
		Email:         email,
		AccessToken:   token,
		EncryptionKey: base64Encode(encKey),
	}

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, data, 0600)
}

func loadSession() (*ConfigSession, error) {
	path, err := getSessionFilePath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no active session. Please login first with 'xora login'")
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var session ConfigSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func base64Decode(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}
