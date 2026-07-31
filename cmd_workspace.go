package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage organization and family workspaces",
	}

	cmd.AddCommand(newWorkspaceListCmd())
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
			
			// Always include the default Personal/sandbox workspace context
			fmt.Fprintln(w, "Personal\tOwner\tfamily\t(sandbox)")

			for _, ws := range workspaces {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ws.Name, ws.Role, ws.Type, ws.ID)
			}
			w.Flush()
			return nil
		},
	}
	return cmd
}
