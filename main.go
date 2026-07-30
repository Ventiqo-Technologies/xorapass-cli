package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	apiURLFlag string
	formatFlag string
)

type DecryptedVaultItem struct {
	Label          string `json:"label"`
	Username       string `json:"username"`
	Value          string `json:"value"`
	Notes          string `json:"notes"`
	Category       string `json:"category"`
	Organization   string `json:"organization"`
	CardholderName string `json:"cardholderName"`
	CardNumber     string `json:"cardNumber"`
	Cvv            string `json:"cvv"`
	ExpiryDate     string `json:"expiryDate"`
	URL            string `json:"url"`
	Hostname       string `json:"hostname"`
	Port           string `json:"port"`
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	Passphrase     string `json:"passphrase"`
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "xora",
		Short: "XoraPass CLI client",
	}

	rootCmd.PersistentFlags().StringVar(&apiURLFlag, "url", "http://localhost:8000", "XoraPass backend core-api server URL")

	var loginCmd = &cobra.Command{
		Use:   "login",
		Short: "Authenticate with XoraPass server via web browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			port := "8500"
			
			// 1. Construct Web Auth URL
			baseURL := strings.TrimRight(apiURLFlag, "/")
			// Replace backend api port 8000 with front-end port 3000 if running locally in dev
			webLoginURL := baseURL + "/cli-login?port=" + port
			if strings.Contains(baseURL, ":8000") {
				webLoginURL = strings.Replace(baseURL, ":8000", ":3000", 1) + "/cli-login?port=" + port
			} else if strings.Contains(baseURL, "app.xorapass.com") {
				// Live production URL mapping
				webLoginURL = "https://app.xorapass.com/cli-login?port=" + port
			}

			fmt.Println("🚀 Starting local callback server on port " + port + "...")
			fmt.Println("🔗 Opening browser for secure authentication...")
			
			// 2. Start callback listener and launch browser
			openBrowser(webLoginURL)

			token, encKey, err := startSSOServer(port)
			if err != nil {
				return fmt.Errorf("web login failed: %w", err)
			}

			// 3. Cache session (CLI extracts email from token claims or uses generic)
			err = saveSession("web-authorized-session", token, encKey)
			if err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}

			fmt.Println("\n✨ Success! Authorized CLI session stored securely.")
			return nil
		},
	}

	var getCmd = &cobra.Command{
		Use:   "secret [secret-name]",
		Short: "Retrieve and decrypt a vault credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretName := args[0]

			session, err := loadSession()
			if err != nil {
				return err
			}

			encKey, err := base64Decode(session.EncryptionKey)
			if err != nil {
				return fmt.Errorf("corrupt session file: %w", err)
			}

			client := NewAPIClient(apiURLFlag)
			entries, err := client.FetchVault(session.AccessToken)
			if err != nil {
				return err
			}

			// Decrypt items local loop search
			var matchedItem *DecryptedVaultItem

			for _, entry := range entries {
				decryptedJSON, err := decryptPayload(entry.EncryptedPayload, entry.Nonce, encKey)
				if err != nil {
					continue // Failed to decrypt this entry with user key
				}

				var item DecryptedVaultItem
				if err := json.Unmarshal([]byte(decryptedJSON), &item); err != nil {
					continue
				}

				if strings.EqualFold(item.Label, secretName) {
					matchedItem = &item
					break
				}
			}

			if matchedItem == nil {
				return fmt.Errorf("secret '%s' not found in vault", secretName)
			}

			if formatFlag == "json" {
				jsonData, err := json.MarshalIndent(matchedItem, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(jsonData))
			} else {
				// Default format output: just print the password value
				fmt.Println(matchedItem.Value)
			}

			return nil
		},
	}

	getCmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "output format (text, json)")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(getCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
