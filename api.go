package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

func (c *APIClient) FetchVault(token, wsID, vaultID string) ([]RawVaultEntry, error) {
	url := c.BaseURL + "/api/vault"
	if wsID != "" && vaultID != "" {
		url = fmt.Sprintf("%s/api/workspaces/%s/vaults/%s/items", c.BaseURL, wsID, vaultID)
	}

	req, err := http.NewRequest("GET", url, nil)
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

func (c *APIClient) CreateVaultEntry(token, wsID, vaultID string, payload EncryptedPayload, nonce string) error {
	reqData := map[string]interface{}{
		"encrypted_payload": payload,
		"nonce":             nonce,
	}
	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return err
	}

	url := c.BaseURL + "/api/vault"
	if wsID != "" && vaultID != "" {
		url = fmt.Sprintf("%s/api/workspaces/%s/vaults/%s/items", c.BaseURL, wsID, vaultID)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create vault entry: status %d", resp.StatusCode)
	}
	return nil
}

func (c *APIClient) UpdateVaultEntry(token, wsID, vaultID, entryID string, payload EncryptedPayload, nonce string) error {
	reqData := map[string]interface{}{
		"encrypted_payload": payload,
		"nonce":             nonce,
	}
	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return err
	}

	url := c.BaseURL + "/api/vault/" + entryID
	if wsID != "" && vaultID != "" {
		url = fmt.Sprintf("%s/api/workspaces/%s/vaults/%s/items/%s", c.BaseURL, wsID, vaultID, entryID)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update vault entry: status %d", resp.StatusCode)
	}
	return nil
}

type ExposureFinding struct {
	ID          string    `json:"id"`
	SecretType  string    `json:"secret_type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Status      string    `json:"status"`
	Destination string    `json:"destination"`
	Location    string    `json:"location"`
	DetectedAt  time.Time `json:"detected_at"`
}

type ExposureSummary struct {
	TotalFindings   int `json:"total"`
	ActiveExposures int `json:"active"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
}

type exposureListResponse struct {
	Findings []ExposureFinding `json:"findings"`
	Count    int               `json:"count"`
}

func (c *APIClient) FetchExposures(token string) ([]ExposureFinding, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/exposures", nil)
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
		return nil, fmt.Errorf("failed to fetch exposure findings: status %d", resp.StatusCode)
	}

	var data exposureListResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data.Findings, nil
}

func (c *APIClient) SummarizeExposures(token string) (*ExposureSummary, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/exposures/summary", nil)
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
		return nil, fmt.Errorf("failed to fetch exposure summary: status %d", resp.StatusCode)
	}

	var summary ExposureSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

func (c *APIClient) DeleteVaultEntry(token, wsID, vaultID string, entryID string) error {
	url := c.BaseURL + "/api/vault/" + entryID
	if wsID != "" && vaultID != "" {
		url = fmt.Sprintf("%s/api/workspaces/%s/vaults/%s/items/%s", c.BaseURL, wsID, vaultID, entryID)
	}

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete vault entry: status %d", resp.StatusCode)
	}
	return nil
}

func (c *APIClient) FetchTrashedEntries(token string) ([]RawVaultEntry, error) {
	url := c.BaseURL + "/api/vault/trash"
	req, err := http.NewRequest("GET", url, nil)
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
		return nil, fmt.Errorf("failed to fetch trash: status %d", resp.StatusCode)
	}

	var items []RawVaultEntry
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	return items, nil
}

func (c *APIClient) RestoreVaultEntry(token, entryID string) error {
	url := fmt.Sprintf("%s/api/vault/%s/restore", c.BaseURL, entryID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to restore vault entry: status %d", resp.StatusCode)
	}
	return nil
}

func (c *APIClient) PermanentDeleteVaultEntry(token, entryID string) error {
	url := fmt.Sprintf("%s/api/vault/%s/permanent", c.BaseURL, entryID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to purge vault entry: status %d", resp.StatusCode)
	}
	return nil
}

type DeviceCodeResponse struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

type DeviceTokenResponse struct {
	Status        string `json:"status"`
	AccessToken   string `json:"access_token,omitempty"`
	EncryptionKey string `json:"encryption_key,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (c *APIClient) RequestDeviceCode() (*DeviceCodeResponse, error) {
	resp, err := c.HTTPClient.Post(c.BaseURL+"/api/auth/device/code", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to request device code: status %d", resp.StatusCode)
	}

	var data DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *APIClient) PollDeviceToken(deviceCode string) (*DeviceTokenResponse, error) {
	reqBody, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	resp, err := c.HTTPClient.Post(c.BaseURL+"/api/auth/device/token", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
		return nil, fmt.Errorf("failed to poll device token: status %d", resp.StatusCode)
	}

	var data DeviceTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

type CLIWorkspace struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	OwnerID string `json:"owner_id"`
}

func (c *APIClient) FetchWorkspaces(token string) ([]CLIWorkspace, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/workspaces", nil)
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
		return nil, fmt.Errorf("failed to fetch workspaces: status %d", resp.StatusCode)
	}

	var workspaces []CLIWorkspace
	if err := json.NewDecoder(resp.Body).Decode(&workspaces); err != nil {
		return nil, err
	}
	return workspaces, nil
}

func (c *APIClient) CreateWorkspace(token, name, wsType string) (*CLIWorkspace, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"name": name,
		"type": wsType,
	})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/workspaces", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create workspace: status %d", resp.StatusCode)
	}

	var ws CLIWorkspace
	if err := json.NewDecoder(resp.Body).Decode(&ws); err != nil {
		return nil, err
	}
	return &ws, nil
}

func (c *APIClient) DeleteWorkspace(token, wsID string) error {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/api/workspaces/"+wsID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete workspace: status %d", resp.StatusCode)
	}
	return nil
}

type CLIVault struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (c *APIClient) FetchWorkspaceVaults(token, wsID string) ([]CLIVault, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/workspaces/"+wsID+"/vaults", nil)
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
		return nil, fmt.Errorf("failed to fetch workspace vaults: status %d", resp.StatusCode)
	}

	var vaults []CLIVault
	if err := json.NewDecoder(resp.Body).Decode(&vaults); err != nil {
		return nil, err
	}
	return vaults, nil
}

func (c *APIClient) CreateWorkspaceVault(token, wsID, name string) (*CLIVault, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"name": name,
	})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/workspaces/"+wsID+"/vaults", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create workspace vault: status %d", resp.StatusCode)
	}

	var v CLIVault
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

type CLISAMLConfiguration struct {
	Configured  bool   `json:"configured"`
	EntityID    string `json:"entity_id"`
	SSOURL      string `json:"sso_url"`
	IdpMetadata string `json:"idp_metadata"`
	Certificate string `json:"certificate"`
}

func (c *APIClient) FetchWorkspaceSAML(token, wsID string) (*CLISAMLConfiguration, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/workspaces/"+wsID+"/saml", nil)
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
		return nil, fmt.Errorf("failed to fetch SAML config: status %d", resp.StatusCode)
	}

	var config CLISAMLConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *APIClient) UpdateWorkspaceSAML(token, wsID, entityID, ssoURL, idpMetadata, certificate string) error {
	reqBody, _ := json.Marshal(map[string]string{
		"entity_id":    entityID,
		"sso_url":      ssoURL,
		"idp_metadata": idpMetadata,
		"certificate":  certificate,
	})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/workspaces/"+wsID+"/saml", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to save SAML config: status %d", resp.StatusCode)
	}
	return nil
}

type CLIWorkspaceDomain struct {
	ID          uint   `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Domain      string `json:"domain"`
	IsVerified  bool   `json:"is_verified"`
	CreatedAt   string `json:"created_at"`
}

func (c *APIClient) FetchWorkspaceDomains(token, wsID string) ([]CLIWorkspaceDomain, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/workspaces/"+wsID+"/domains", nil)
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
		return nil, fmt.Errorf("failed to fetch domains: status %d", resp.StatusCode)
	}

	var domains []CLIWorkspaceDomain
	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return nil, err
	}
	return domains, nil
}

func (c *APIClient) AddWorkspaceDomain(token, wsID, domain string) (*CLIWorkspaceDomain, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"domain": domain,
	})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/workspaces/"+wsID+"/domains", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorDetail struct {
			Detail string `json:"detail"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorDetail); err == nil && errorDetail.Detail != "" {
			return nil, fmt.Errorf("%s", errorDetail.Detail)
		}
		return nil, fmt.Errorf("failed to add domain: status %d", resp.StatusCode)
	}

	var newDomain CLIWorkspaceDomain
	if err := json.NewDecoder(resp.Body).Decode(&newDomain); err != nil {
		return nil, err
	}
	return &newDomain, nil
}

func (c *APIClient) DeleteWorkspaceDomain(token, wsID, domain string) error {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/api/workspaces/"+wsID+"/domains/"+url.QueryEscape(domain), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorDetail struct {
			Detail string `json:"detail"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorDetail); err == nil && errorDetail.Detail != "" {
			return fmt.Errorf("%s", errorDetail.Detail)
		}
		return fmt.Errorf("failed to delete domain: status %d", resp.StatusCode)
	}
	return nil
}
