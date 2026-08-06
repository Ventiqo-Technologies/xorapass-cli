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

func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage organization and family workspaces",
	}

	cmd.AddCommand(newWorkspaceListCmd())
	cmd.AddCommand(newWorkspaceStatusCmd())
	cmd.AddCommand(newWorkspaceUseCmd())
	cmd.AddCommand(newWorkspaceCreateCmd())
	cmd.AddCommand(newWorkspaceDeleteCmd())
	return cmd
}

func newWorkspaceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all active workspaces you belong to",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			workspaces, err := client.FetchWorkspaces(session.AccessToken)
			if err != nil {
				return err
			}

			if formatFlag == "json" {
				data, _ := json.MarshalIndent(workspaces, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			// Render standard text table format
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "WORKSPACE NAME\tROLE\tTYPE\tWORKSPACE ID")
			
			// Mark active workspace in the list
			persName := "Personal"
			if session.ActiveWorkspaceID == "" || session.ActiveWorkspaceID == "sandbox" {
				persName = "Personal *"
			}
			fmt.Fprintln(w, persName+"\tOwner\tfamily\t(sandbox)")

			for _, ws := range workspaces {
				name := ws.Name
				if session.ActiveWorkspaceID == ws.ID {
					name = ws.Name + " *"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, ws.Role, ws.Type, ws.ID)
			}
			w.Flush()
			return nil
		},
	}
	return cmd
}

func newWorkspaceStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show currently active workspace context",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			if session.ActiveWorkspaceID == "" || session.ActiveWorkspaceID == "sandbox" {
				fmt.Println("Active Workspace: Personal (sandbox)")
				return nil
			}

			// Fetch name of active workspace from API to be user friendly
			client := NewAPIClient(apiURLFlag)
			workspaces, err := client.FetchWorkspaces(session.AccessToken)
			if err != nil {
				fmt.Printf("Active Workspace ID: %s (Failed to fetch name: %v)\n", session.ActiveWorkspaceID, err)
				return nil
			}

			for _, ws := range workspaces {
				if ws.ID == session.ActiveWorkspaceID {
					fmt.Printf("Active Workspace: %s (%s, role: %s)\n", ws.Name, ws.ID, ws.Role)
					if session.ActiveVaultID != "" {
						fmt.Printf("Active Vault ID: %s\n", session.ActiveVaultID)
					} else {
						fmt.Println("No active vault context. Run 'xora vault use <vault>' to target a shared vault.")
					}
					return nil
				}
			}

			fmt.Printf("Active Workspace ID: %s (You are no longer a member of this workspace)\n", session.ActiveWorkspaceID)
			return nil
		},
	}
	return cmd
}

func newWorkspaceUseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use [workspace-name-or-id]",
		Short: "Switch active workspace context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			if strings.EqualFold(target, "personal") || strings.EqualFold(target, "sandbox") || target == "" {
				session.ActiveWorkspaceID = ""
				session.ActiveVaultID = ""
				rawSession, _ := json.Marshal(session)
				homeDir, _ := os.UserHomeDir()
				sessionPath := filepath.Join(homeDir, ".xora", "session.json")
				err = ioutil.WriteFile(sessionPath, rawSession, 0600)
				if err != nil {
					return err
				}
				fmt.Println("Switched workspace context to Personal (sandbox).")
				return nil
			}

			client := NewAPIClient(apiURLFlag)
			workspaces, err := client.FetchWorkspaces(session.AccessToken)
			if err != nil {
				return err
			}

			var matched *CLIWorkspace
			for i, ws := range workspaces {
				if ws.ID == target || strings.EqualFold(ws.Name, target) {
					matched = &workspaces[i]
					break
				}
			}

			if matched == nil {
				return fmt.Errorf("no active workspace found matching '%s'", target)
			}

			session.ActiveWorkspaceID = matched.ID
			// Automatically reset the active vault context when switching workspaces to avoid cross-workspace leak
			session.ActiveVaultID = ""

			// Save session with active context properties
			rawSession, _ := json.Marshal(session)
			homeDir, _ := os.UserHomeDir()
			sessionPath := filepath.Join(homeDir, ".xora", "session.json")
			err = ioutil.WriteFile(sessionPath, rawSession, 0600)
			if err != nil {
				return err
			}

			fmt.Printf("Switched workspace context to: %s (%s)\n", matched.Name, matched.ID)
			fmt.Println("Note: Workspace vault context has been reset. Run 'xora vault use <vault>' to target a vault.")
			return nil
		},
	}
	return cmd
}

func newWorkspaceCreateCmd() *cobra.Command {
	var typeFlag string

	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new organization or family workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			ws, err := client.CreateWorkspace(session.AccessToken, name, typeFlag)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully created workspace '%s' (%s, type: %s)!\n", ws.Name, ws.ID, ws.Type)
			return nil
		},
	}

	cmd.Flags().StringVar(&typeFlag, "type", "organization", "type of workspace (organization, family, business)")
	return cmd
}

// Quick path resolution helper for saving configuration
func filepathJoin(elem ...string) string {
	return filepath.Join(elem...)
}

func newWorkspaceDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [workspace-name-or-id]",
		Short: "Permanently delete an organization or family workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			workspaces, err := client.FetchWorkspaces(session.AccessToken)
			if err != nil {
				return err
			}

			var matchedID string
			var matchedName string
			for _, ws := range workspaces {
				if ws.ID == target || strings.EqualFold(ws.Name, target) {
					matchedID = ws.ID
					matchedName = ws.Name
					break
				}
			}

			if matchedID == "" {
				return fmt.Errorf("no workspace found matching '%s'", target)
			}

			// Prompt confirmation
			fmt.Printf("WARNING: Permanently deleting workspace '%s' will erase all shared vaults, credentials, groups, and members. This action cannot be undone.\n", matchedName)
			fmt.Print("Type 'YES' to confirm: ")
			var confirmInput string
			_, err = fmt.Scanln(&confirmInput)
			if err != nil || confirmInput != "YES" {
				fmt.Println("Workspace deletion cancelled.")
				return nil
			}

			err = client.DeleteWorkspace(session.AccessToken, matchedID)
			if err != nil {
				return err
			}

			// If deleted workspace was the active context, reset local session context
			if session.ActiveWorkspaceID == matchedID {
				session.ActiveWorkspaceID = ""
				session.ActiveVaultID = ""
				rawSession, _ := json.Marshal(session)
				homeDir, _ := os.UserHomeDir()
				sessionPath := filepath.Join(homeDir, ".xora", "session.json")
				err = ioutil.WriteFile(sessionPath, rawSession, 0600)
				if err != nil {
					return err
				}
			}

			fmt.Printf("Successfully deleted workspace '%s' permanently.\n", matchedName)
			return nil
		},
	}
	return cmd
}
