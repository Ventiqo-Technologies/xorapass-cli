package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
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
		Short: "Authenticate with XoraPass server",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := bufio.NewReader(os.Stdin)

			fmt.Print("Email: ")
			email, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			email = strings.TrimSpace(email)

			fmt.Print("Master Password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			fmt.Println() // Print newline after hidden input
			password := strings.TrimSpace(string(bytePassword))

			client := NewAPIClient(apiURLFlag)

			// Step 1: Discover salt
			fmt.Println("Connecting to server...")
			discoverData, err := client.Discover(email)
			if err != nil {
				return fmt.Errorf("connection error: %w", err)
			}

			// Step 2: Key Derivation
			fmt.Println("Deriving master key (Argon2id)...")
			masterKey, err := deriveMasterKey(password, discoverData.MasterSalt)
			if err != nil {
				return err
			}

			encKey, clientAuthHash, err := splitMasterKey(masterKey)
			if err != nil {
				return err
			}

			// Step 3: Login HTTP POST
			fmt.Println("Authenticating...")
			loginData, err := client.Login(email, clientAuthHash)
			if err != nil {
				return err
			}

			if loginData.MfaRequired {
				return errors.New("multifactor authentication is enabled. CLI mfa flow is currently not implemented")
			}

			// Step 4: Cache session
			err = saveSession(email, loginData.AccessToken, encKey)
			if err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}

			fmt.Println("Success! Session stored securely.")
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
