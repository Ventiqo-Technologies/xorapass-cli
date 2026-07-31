package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// decodeSession loads and validates the current session
func decodeSession() (*ConfigSession, []byte, error) {
	session, err := loadSession()
	if err != nil {
		return nil, nil, err
	}
	encKey, err := base64Decode(session.EncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("corrupt session file: %w", err)
	}
	return session, encKey, nil
}

// decryptAll fetches and decrypts all vault entries
func decryptAll(session *ConfigSession, encKey []byte, apiURL string) ([]DecryptedVaultItem, []string, error) {
	client := NewAPIClient(apiURL)
	entries, err := client.FetchVault(session.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	var items []DecryptedVaultItem
	var ids []string
	for _, entry := range entries {
		decryptedJSON, err := decryptPayload(entry.EncryptedPayload, entry.Nonce, encKey)
		if err != nil {
			continue
		}
		var item DecryptedVaultItem
		if err := jsonUnmarshal([]byte(decryptedJSON), &item); err != nil {
			continue
		}
		items = append(items, item)
		ids = append(ids, entry.ID)
	}
	return items, ids, nil
}

// findEntry finds an entry by label (case-insensitive)
func findEntry(items []DecryptedVaultItem, ids []string, name string) (*DecryptedVaultItem, string, error) {
	for i, item := range items {
		if strings.EqualFold(item.Label, name) {
			return &items[i], ids[i], nil
		}
	}
	return nil, "", fmt.Errorf("no entry found matching '%s'", name)
}

// printItemText prints a human-readable summary of a vault item
func printItemText(item *DecryptedVaultItem) {
	fmt.Printf("Label:    %s\n", item.Label)
	if item.Username != "" {
		fmt.Printf("Username: %s\n", item.Username)
	}
	if item.Value != "" {
		fmt.Printf("Password: %s\n", item.Value)
	}
	if item.URL != "" {
		fmt.Printf("URL:      %s\n", item.URL)
	}
	if item.Notes != "" {
		fmt.Printf("Notes:    %s\n", item.Notes)
	}
	if item.Category != "" {
		fmt.Printf("Category: %s\n", item.Category)
	}
}

// printItemEnv prints KEY=VALUE env format
func printItemEnv(item *DecryptedVaultItem) {
	label := strings.ToUpper(strings.ReplaceAll(item.Label, " ", "_"))
	if item.Value != "" {
		fmt.Printf("%s_PASSWORD=%s\n", label, item.Value)
	}
	if item.Username != "" {
		fmt.Printf("%s_USERNAME=%s\n", label, item.Username)
	}
	if item.URL != "" {
		fmt.Printf("%s_URL=%s\n", label, item.URL)
	}
}



// sessionFilePath returns the path to the session file
func sessionFilePath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".xora", "session.json")
}

// ---- LOGOUT COMMAND ----

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear the current CLI session",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := sessionFilePath()
			if _, err := os.Stat(path); os.IsNotExist(err) {
				fmt.Println("No active session found.")
				return nil
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove session: %w", err)
			}
			fmt.Println("Logged out successfully.")
			return nil
		},
	}
}

// ---- WHOAMI COMMAND ----

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current session info",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := loadSession()
			if err != nil {
				return err
			}
			fmt.Printf("Email:  %s\n", session.Email)
			fmt.Printf("Session file: %s\n", sessionFilePath())
			return nil
		},
	}
}
