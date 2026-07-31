package main

import (
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

	rootCmd.PersistentFlags().StringVar(&apiURLFlag, "url", "https://app.xorapass.com", "XoraPass backend core-api server URL")

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

			fmt.Println("Starting local callback server on port " + port + "...")
			fmt.Println("Opening browser for secure authentication...")
			
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

			fmt.Println("\nSuccess! Authorized CLI session stored securely.")
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVarP(&formatFlag, "format", "f", "text", "output format (text, json, env)")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(newLogoutCmd())
	rootCmd.AddCommand(newWhoamiCmd())
	rootCmd.AddCommand(newListCmd())
	rootCmd.AddCommand(newGetCmd())
	rootCmd.AddCommand(newSearchCmd())
	rootCmd.AddCommand(newAddCmd())
	rootCmd.AddCommand(newDeleteCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
