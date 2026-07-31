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
	var username string
	var password string
	var url string
	var notes string
	var category string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new vault entry",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			// Interactive prompt if flags are empty
			reader := bufio.NewReader(os.Stdin)
			if label == "" {
				fmt.Print("Enter Label (required): ")
				label, _ = reader.ReadString('\n')
				label = strings.TrimSpace(label)
				if label == "" {
					return fmt.Errorf("label is required")
				}
			}
			if username == "" {
				fmt.Print("Enter Username: ")
				username, _ = reader.ReadString('\n')
				username = strings.TrimSpace(username)
			}
			if password == "" {
				fmt.Print("Enter Password: ")
				password, _ = reader.ReadString('\n')
				password = strings.TrimSpace(password)
			}
			if url == "" {
				fmt.Print("Enter URL: ")
				url, _ = reader.ReadString('\n')
				url = strings.TrimSpace(url)
			}
			if notes == "" {
				fmt.Print("Enter Notes: ")
				notes, _ = reader.ReadString('\n')
				notes = strings.TrimSpace(notes)
			}
			if category == "" {
				fmt.Print("Enter Category (login, card, note, sshkey, other) [default: login]: ")
				category, _ = reader.ReadString('\n')
				category = strings.TrimSpace(strings.ToLower(category))
				if category == "" {
					category = "login"
				}
			} else {
				category = strings.ToLower(category)
			}

			// Validate category matches one of the valid frontend categories
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

			item := DecryptedVaultItem{
				Label:        label,
				Username:     username,
				Value:        password,
				URL:          url,
				Notes:        notes,
				Category:     category,
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
			err = client.CreateVaultEntry(session.AccessToken, payload, nonce)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully added entry '%s' to vault.\n", label)
			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "", "Label of the entry")
	cmd.Flags().StringVar(&username, "username", "", "Username")
	cmd.Flags().StringVar(&password, "password", "", "Password")
	cmd.Flags().StringVar(&url, "url", "", "URL")
	cmd.Flags().StringVar(&notes, "notes", "", "Notes")
	cmd.Flags().StringVar(&category, "category", "", "Category")

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
			err = client.DeleteVaultEntry(session.AccessToken, entryID)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully deleted entry '%s' (moved to trash).\n", secretName)
			return nil
		},
	}

	return cmd
}
