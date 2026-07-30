package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewAPIClient(baseURL string) *APIClient {
	return &APIClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type DiscoverResponse struct {
	Exists     bool   `json:"exists"`
	MasterSalt string `json:"master_salt"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	MfaRequired bool   `json:"mfa_required"`
	MfaToken    string `json:"mfa_token"`
}

type RawVaultEntry struct {
	ID               string           `json:"id"`
	EncryptedPayload EncryptedPayload `json:"encrypted_payload"`
	Nonce            string           `json:"nonce"`
}

func (c *APIClient) Discover(email string) (*DiscoverResponse, error) {
	reqBody, _ := json.Marshal(map[string]string{"email": email})
	resp, err := c.HTTPClient.Post(c.BaseURL+"/api/auth/discover", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover failed: status %d", resp.StatusCode)
	}

	var data DiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *APIClient) Login(email, clientAuthHash string) (*LoginResponse, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"email":            email,
		"client_auth_hash": clientAuthHash,
	})
	resp, err := c.HTTPClient.Post(c.BaseURL+"/api/auth/login", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		if detail, ok := errData["detail"]; ok {
			return nil, fmt.Errorf("login failed: %s", detail)
		}
		return nil, fmt.Errorf("login failed: status %d", resp.StatusCode)
	}

	var data LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *APIClient) FetchVault(token string) ([]RawVaultEntry, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/vault", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch vault: status %d", resp.StatusCode)
	}

	var entries []RawVaultEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}
