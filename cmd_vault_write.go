package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// ---- ADD COMMAND ----

func newAddCmd() *cobra.Command {
	var label string
	var category string
	
	// Optional flags to bypass interactive prompts entirely (DevOps/scripting use case)
	var username string
	var password string
	var url string
	var notes string
	var cardholderName string
	var cardNumber string
	var expiryDate string
	var cvv string
	var privateKey string
	var publicKey string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new vault entry",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			reader := bufio.NewReader(os.Stdin)

			// 1. Determine category
			if category == "" {
				fmt.Print("Choose Category (login, card, note, sshkey, other) [default: login]: ")
				category, _ = reader.ReadString('\n')
				category = strings.TrimSpace(strings.ToLower(category))
				if category == "" {
					category = "login"
				}
			} else {
				category = strings.ToLower(category)
			}

			validCategories := map[string]bool{
				"login":  true,
				"card":   true,
				"note":   true,
				"sshkey": true,
				"other":  true,
			}
			if !validCategories[category] {
				fmt.Printf("Warning: '%s' is not a standard category. Defaulting to 'login' for best Web UI compatibility.\n", category)
				category = "login"
			}

			// 2. Determine Label
			if label == "" {
				fmt.Print("Enter Label/Name (required): ")
				label, _ = reader.ReadString('\n')
				label = strings.TrimSpace(label)
				if label == "" {
					return fmt.Errorf("label is required")
				}
			}

			item := DecryptedVaultItem{
				Label:    label,
				Category: category,
			}

			// 3. Category-specific interactive prompts
			switch category {
			case "login":
				if username == "" {
					fmt.Print("Enter Username: ")
					username, _ = reader.ReadString('\n')
					item.Username = strings.TrimSpace(username)
				} else {
					item.Username = username
				}
				if password == "" {
					fmt.Print("Enter Password: ")
					password, _ = reader.ReadString('\n')
					item.Value = strings.TrimSpace(password)
				} else {
					item.Value = password
				}
				if url == "" {
					fmt.Print("Enter Website URL: ")
					url, _ = reader.ReadString('\n')
					item.URL = strings.TrimSpace(url)
				} else {
					item.URL = url
				}
				if notes == "" {
					fmt.Print("Enter Notes: ")
					notes, _ = reader.ReadString('\n')
					item.Notes = strings.TrimSpace(notes)
				} else {
					item.Notes = notes
				}

			case "card":
				if cardholderName == "" {
					fmt.Print("Enter Cardholder Name: ")
					cardholderName, _ = reader.ReadString('\n')
					item.CardholderName = strings.TrimSpace(cardholderName)
				} else {
					item.CardholderName = cardholderName
				}
				if cardNumber == "" {
					fmt.Print("Enter Card Number: ")
					cardNumber, _ = reader.ReadString('\n')
					cardNumber = strings.TrimSpace(cardNumber)
				}
				// Remove any existing spaces, dashes, or non-digits to sanitize
				var cleanCard string
				for _, char := range cardNumber {
					if char >= '0' && char <= '9' {
						cleanCard += string(char)
					}
				}
				// Format with spaces every 4 digits (standard card representation)
				var formattedCard strings.Builder
				for i, r := range cleanCard {
					if i > 0 && i%4 == 0 {
						formattedCard.WriteRune(' ')
					}
					formattedCard.WriteRune(r)
				}
				item.CardNumber = formattedCard.String()
				if expiryDate == "" {
					fmt.Print("Enter Expiry Date (MM/YY): ")
					expiryDate, _ = reader.ReadString('\n')
					item.ExpiryDate = strings.TrimSpace(expiryDate)
				} else {
					item.ExpiryDate = expiryDate
				}
				if cvv == "" {
					fmt.Print("Enter CVV: ")
					cvv, _ = reader.ReadString('\n')
					item.Cvv = strings.TrimSpace(cvv)
				} else {
					item.Cvv = cvv
				}
				if notes == "" {
					fmt.Print("Enter Notes: ")
					notes, _ = reader.ReadString('\n')
					item.Notes = strings.TrimSpace(notes)
				} else {
					item.Notes = notes
				}

			case "note":
				if notes == "" {
					fmt.Print("Enter Secure Note Body: ")
					notes, _ = reader.ReadString('\n')
					item.Notes = strings.TrimSpace(notes)
				} else {
					item.Notes = notes
				}

			case "sshkey":
				if privateKey == "" {
					fmt.Print("Enter Private Key: ")
					privateKey, _ = reader.ReadString('\n')
					item.PrivateKey = strings.TrimSpace(privateKey)
				} else {
					item.PrivateKey = privateKey
				}
				if publicKey == "" {
					fmt.Print("Enter Public Key: ")
					publicKey, _ = reader.ReadString('\n')
					item.PublicKey = strings.TrimSpace(publicKey)
				} else {
					item.PublicKey = publicKey
				}
				if passphrase == "" {
					fmt.Print("Enter Passphrase (if any): ")
					passphrase, _ = reader.ReadString('\n')
					item.Passphrase = strings.TrimSpace(passphrase)
				} else {
					item.Passphrase = passphrase
				}
				if notes == "" {
					fmt.Print("Enter Notes: ")
					notes, _ = reader.ReadString('\n')
					item.Notes = strings.TrimSpace(notes)
				} else {
					item.Notes = notes
				}

			case "other":
				if username == "" {
					fmt.Print("Enter Username/Key: ")
					username, _ = reader.ReadString('\n')
					item.Username = strings.TrimSpace(username)
				} else {
					item.Username = username
				}
				if password == "" {
					fmt.Print("Enter Value/Secret: ")
					password, _ = reader.ReadString('\n')
					item.Value = strings.TrimSpace(password)
				} else {
					item.Value = password
				}
				if url == "" {
					fmt.Print("Enter URL/Host: ")
					url, _ = reader.ReadString('\n')
					item.URL = strings.TrimSpace(url)
				} else {
					item.URL = url
				}
				if notes == "" {
					fmt.Print("Enter Notes: ")
					notes, _ = reader.ReadString('\n')
					item.Notes = strings.TrimSpace(notes)
				} else {
					item.Notes = notes
				}
			}

			// Encrypt item payload
			plaintext, err := json.Marshal(item)
			if err != nil {
				return err
			}

			payload, nonce, err := encryptPayload(string(plaintext), encKey)
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			err = client.CreateVaultEntry(session.AccessToken, session.ActiveWorkspaceID, session.ActiveVaultID, payload, nonce)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully added entry '%s' under category '%s' to vault.\n", label, category)
			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "", "Label of the entry")
	cmd.Flags().StringVar(&category, "category", "", "Category (login, card, note, sshkey, other)")
	
	// Flags to bypass prompts in scripts
	cmd.Flags().StringVar(&username, "username", "", "Username / Key")
	cmd.Flags().StringVar(&password, "password", "", "Password / Value / Secret")
	cmd.Flags().StringVar(&url, "url", "", "URL / Host")
	cmd.Flags().StringVar(&notes, "notes", "", "Notes / Secure Note Body")
	cmd.Flags().StringVar(&cardholderName, "cardholder", "", "Cardholder Name (for category card)")
	cmd.Flags().StringVar(&cardNumber, "cardnumber", "", "Card Number (for category card)")
	cmd.Flags().StringVar(&expiryDate, "expiry", "", "Expiry Date (for category card)")
	cmd.Flags().StringVar(&cvv, "cvv", "", "CVV (for category card)")
	cmd.Flags().StringVar(&privateKey, "privatekey", "", "Private Key (for category sshkey)")
	cmd.Flags().StringVar(&publicKey, "publickey", "", "Public Key (for category sshkey)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Passphrase (for category sshkey)")

	return cmd
}

// ---- DELETE COMMAND ----

func newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [secret-name]",
		Short: "Delete a vault entry (move to trash)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretName := args[0]

			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, ids, err := decryptAll(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			_, entryID, err := findEntry(items, ids, secretName)
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			err = client.DeleteVaultEntry(session.AccessToken, session.ActiveWorkspaceID, session.ActiveVaultID, entryID)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully deleted entry '%s' (moved to trash).\n", secretName)
			return nil
		},
	}

	return cmd
}
