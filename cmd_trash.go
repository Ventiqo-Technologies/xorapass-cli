package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newTrashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trash",
		Short: "Manage soft-deleted vault credentials",
	}

	cmd.AddCommand(newTrashListCmd())
	cmd.AddCommand(newTrashRestoreCmd())
	cmd.AddCommand(newTrashPurgeCmd())
	return cmd
}

func newTrashListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all items in the trash",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, _, err := decryptTrash(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			if len(items) == 0 {
				fmt.Println("Trash is empty.")
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

			// Render tabular text format
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
	return cmd
}

func newTrashRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore [secret-name-or-id]",
		Short: "Restore a soft-deleted item from the trash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, ids, err := decryptTrash(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			// Try to find match by name or exact ID
			var matchedID string
			var matchedLabel string
			for i, item := range items {
				if ids[i] == target || strings.EqualFold(item.Label, target) {
					matchedID = ids[i]
					matchedLabel = item.Label
					break
				}
			}

			if matchedID == "" {
				return fmt.Errorf("no trashed item found matching '%s'", target)
			}

			client := NewAPIClient(apiURLFlag)
			err = client.RestoreVaultEntry(session.AccessToken, matchedID)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully restored entry '%s' back to vault.\n", matchedLabel)
			return nil
		},
	}
	return cmd
}

func newTrashPurgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "purge [secret-name-or-id]",
		Short: "Permanently delete a soft-deleted item from the trash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, ids, err := decryptTrash(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			var matchedID string
			var matchedLabel string
			for i, item := range items {
				if ids[i] == target || strings.EqualFold(item.Label, target) {
					matchedID = ids[i]
					matchedLabel = item.Label
					break
				}
			}

			if matchedID == "" {
				return fmt.Errorf("no trashed item found matching '%s'", target)
			}

			client := NewAPIClient(apiURLFlag)
			err = client.PermanentDeleteVaultEntry(session.AccessToken, matchedID)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully purged entry '%s' permanently.\n", matchedLabel)
			return nil
		},
	}
	return cmd
}

// decryptTrash fetches and decrypts all soft-deleted vault entries
func decryptTrash(session *ConfigSession, encKey []byte, apiURL string) ([]DecryptedVaultItem, []string, error) {
	client := NewAPIClient(apiURL)
	entries, err := client.FetchTrashedEntries(session.AccessToken)
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
		if err := json.Unmarshal([]byte(decryptedJSON), &item); err != nil {
			continue
		}
		items = append(items, item)
		ids = append(ids, entry.ID)
	}
	return items, ids, nil
}
