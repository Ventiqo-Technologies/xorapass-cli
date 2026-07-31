package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newVaultMgmtCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage shared organization and family vaults",
	}

	cmd.AddCommand(newVaultListCmd())
	cmd.AddCommand(newVaultUseCmd())
	cmd.AddCommand(newVaultCreateCmd())
	return cmd
}

func newVaultListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all shared vaults in the active workspace context",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			if session.ActiveWorkspaceID == "" || session.ActiveWorkspaceID == "sandbox" {
				fmt.Println("You are currently in the Personal (sandbox) workspace.")
				fmt.Println("Personal workspace has a single default vault. Switch to an organization workspace to see shared vaults:")
				fmt.Println("  xora workspace list")
				fmt.Println("  xora workspace use <workspace>")
				return nil
			}

			client := NewAPIClient(apiURLFlag)
			vaults, err := client.FetchWorkspaceVaults(session.AccessToken, session.ActiveWorkspaceID)
			if err != nil {
				return err
			}

			if formatFlag == "json" {
				data, _ := json.MarshalIndent(vaults, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			if len(vaults) == 0 {
				fmt.Println("No shared vaults found in this workspace. Run 'xora vault create <name>' to create one.")
				return nil
			}

			// Render standard text table format
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "VAULT NAME\tDESCRIPTION\tVAULT ID")
			
			for _, v := range vaults {
				name := v.Name
				if session.ActiveVaultID == v.ID {
					name = v.Name + " *"
				}
				desc := v.Description
				if desc == "" {
					desc = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", name, desc, v.ID)
			}
			w.Flush()
			return nil
		},
	}
	return cmd
}

func newVaultUseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use [vault-name-or-id]",
		Short: "Switch active vault context in the active workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			if session.ActiveWorkspaceID == "" || session.ActiveWorkspaceID == "sandbox" {
				return fmt.Errorf("you are in the Personal workspace which has only a single default vault. Switch to an organization workspace first")
			}

			client := NewAPIClient(apiURLFlag)
			vaults, err := client.FetchWorkspaceVaults(session.AccessToken, session.ActiveWorkspaceID)
			if err != nil {
				return err
			}

			var matched *CLIVault
			for i, v := range vaults {
				if v.ID == target || strings.EqualFold(v.Name, target) {
					matched = &vaults[i]
					break
				}
			}

			if matched == nil {
				return fmt.Errorf("no vault found matching '%s' in the active workspace", target)
			}

			session.ActiveVaultID = matched.ID

			// Save session properties
			rawSession, _ := json.Marshal(session)
			homeDir, _ := os.UserHomeDir()
			sessionPath := filepath.Join(homeDir, ".xora", "session.json")
			err = ioutil.WriteFile(sessionPath, rawSession, 0600)
			if err != nil {
				return err
			}

			fmt.Printf("Switched active vault context to: %s (%s)\n", matched.Name, matched.ID)
			return nil
		},
	}
	return cmd
}

func newVaultCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new shared vault inside the active workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			if session.ActiveWorkspaceID == "" || session.ActiveWorkspaceID == "sandbox" {
				return fmt.Errorf("cannot create vaults in Personal workspace. Switch to an organization workspace first")
			}

			client := NewAPIClient(apiURLFlag)
			v, err := client.CreateWorkspaceVault(session.AccessToken, session.ActiveWorkspaceID, name)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully created shared vault '%s' (%s)!\n", v.Name, v.ID)
			return nil
		},
	}
	return cmd
}
