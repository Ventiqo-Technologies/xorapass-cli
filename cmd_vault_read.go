package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"os"

	"github.com/spf13/cobra"
)

// Helper to deserialize json since cmd_auth.go needs it
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// ---- LIST COMMAND ----

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all vault entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, _, err := decryptAll(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			if len(items) == 0 {
				fmt.Println("No entries found in vault.")
				return nil
			}

			if formatFlag == "json" {
				jsonData, err := json.MarshalIndent(items, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(jsonData))
				return nil
			}

			// Plain text table format
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "LABEL\tUSERNAME\tCATEGORY\tURL")
			for _, item := range items {
				username := item.Username
				if username == "" {
					username = "-"
				}
				category := item.Category
				if category == "" {
					category = "-"
				}
				url := item.URL
				if url == "" {
					url = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.Label, username, category, url)
			}
			w.Flush()
			return nil
		},
	}
}

// ---- GET COMMAND ----

func newGetCmd() *cobra.Command {
	var fieldFlag string

	cmd := &cobra.Command{
		Use:   "get [secret-name]",
		Short: "Retrieve and decrypt a vault credential",
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

			matchedItem, _, err := findEntry(items, ids, secretName)
			if err != nil {
				return err
			}

			if formatFlag == "json" {
				jsonData, err := json.MarshalIndent(matchedItem, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(jsonData))
				return nil
			} else if formatFlag == "env" {
				printItemEnv(matchedItem)
				return nil
			}

			// Specific field retrieval
			if fieldFlag != "" {
				switch strings.ToLower(fieldFlag) {
				case "password", "value":
					fmt.Println(matchedItem.Value)
				case "username":
					fmt.Println(matchedItem.Username)
				case "url":
					fmt.Println(matchedItem.URL)
				case "notes":
					fmt.Println(matchedItem.Notes)
				case "cardnumber":
					fmt.Println(matchedItem.CardNumber)
				case "cardholder":
					fmt.Println(matchedItem.CardholderName)
				case "expiry":
					fmt.Println(matchedItem.ExpiryDate)
				case "cvv":
					fmt.Println(matchedItem.Cvv)
				case "privatekey":
					fmt.Println(matchedItem.PrivateKey)
				case "publickey":
					fmt.Println(matchedItem.PublicKey)
				case "passphrase":
					fmt.Println(matchedItem.Passphrase)
				default:
					return fmt.Errorf("unknown field '%s'", fieldFlag)
				}
				return nil
			}

			// Smart defaults by category
			switch matchedItem.Category {
			case "card":
				fmt.Printf("Cardholder:      %s\n", matchedItem.CardholderName)
				fmt.Printf("Card Number:     %s\n", matchedItem.CardNumber)
				fmt.Printf("Expiry Date:     %s\n", matchedItem.ExpiryDate)
				fmt.Printf("CVV:             %s\n", matchedItem.Cvv)
				if matchedItem.Notes != "" {
					fmt.Printf("Notes:           %s\n", matchedItem.Notes)
				}
			case "sshkey":
				fmt.Printf("Private Key:\n%s\n\n", matchedItem.PrivateKey)
				if matchedItem.PublicKey != "" {
					fmt.Printf("Public Key:  %s\n", matchedItem.PublicKey)
				}
				if matchedItem.Passphrase != "" {
					fmt.Printf("Passphrase:  %s\n", matchedItem.Passphrase)
				}
				if matchedItem.Notes != "" {
					fmt.Printf("Notes:       %s\n", matchedItem.Notes)
				}
			case "note":
				fmt.Println(matchedItem.Notes)
			default:
				// For logins or default categories, print just the password value (highly pipe-friendly)
				fmt.Println(matchedItem.Value)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&fieldFlag, "field", "", "Extract a specific field (username, password, url, notes, cardnumber, cardholder, expiry, cvv, privatekey, publickey, passphrase)")
	return cmd
}

// ---- SEARCH COMMAND ----

func newSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search [query]",
		Short: "Fuzzy search vault entries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := strings.ToLower(args[0])

			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, _, err := decryptAll(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			var matched []DecryptedVaultItem
			for _, item := range items {
				if strings.Contains(strings.ToLower(item.Label), query) ||
					strings.Contains(strings.ToLower(item.Username), query) ||
					strings.Contains(strings.ToLower(item.URL), query) {
					matched = append(matched, item)
				}
			}

			if len(matched) == 0 {
				fmt.Println("No matches found.")
				return nil
			}

			if formatFlag == "json" {
				jsonData, err := json.MarshalIndent(matched, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(jsonData))
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "LABEL\tUSERNAME\tCATEGORY\tURL")
			for _, item := range matched {
				username := item.Username
				if username == "" {
					username = "-"
				}
				category := item.Category
				if category == "" {
					category = "-"
				}
				url := item.URL
				if url == "" {
					url = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.Label, username, category, url)
			}
			w.Flush()
			return nil
		},
	}
}
