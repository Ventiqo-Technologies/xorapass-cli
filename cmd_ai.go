package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newAICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "Manage AI credential access and bridge tokens",
	}

	cmd.AddCommand(newAIRequestsCmd())
	cmd.AddCommand(newAIApproveCmd())
	cmd.AddCommand(newAIDenyCmd())
	cmd.AddCommand(newAITokenCmd())
	return cmd
}

func newAIRequestsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List pending AI credential access requests requiring approval",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			requests, err := client.FetchAIRequests(session.AccessToken)
			if err != nil {
				return err
			}

			if formatFlag == "json" {
				data, _ := json.MarshalIndent(requests, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			if len(requests) == 0 {
				fmt.Println("No pending AI access requests.")
				return nil
			}

			// Render standard text table format
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "REQUEST ID\tCREDENTIAL\tDOMAIN\tRISK\tSTATUS")
			for _, r := range requests {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s (%d)\t%s\n", r.ID, r.CredentialName, r.TargetDomain, r.RiskLevel, r.RiskScore, r.Status)
			}
			w.Flush()
			return nil
		},
	}
	return cmd
}

func newAIApproveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve [request-id]",
		Short: "Approve a pending AI access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestID := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			err = client.ApproveAIRequest(session.AccessToken, requestID)
			if err != nil {
				return err
			}

			fmt.Println("AI access request approved successfully!")
			return nil
		},
	}
	return cmd
}

func newAIDenyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deny [request-id]",
		Short: "Deny a pending AI access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestID := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			err = client.DenyAIRequest(session.AccessToken, requestID)
			if err != nil {
				return err
			}

			fmt.Println("AI access request denied successfully.")
			return nil
		},
	}
	return cmd
}

func newAITokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage AI bridge tokens",
	}

	cmd.AddCommand(newAITokenListCmd())
	cmd.AddCommand(newAITokenCreateCmd())
	cmd.AddCommand(newAITokenRevokeCmd())
	return cmd
}

func newAITokenListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all active AI bridge tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			tokens, err := client.FetchBridgeTokens(session.AccessToken)
			if err != nil {
				return err
			}

			if formatFlag == "json" {
				data, _ := json.MarshalIndent(tokens, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			if len(tokens) == 0 {
				fmt.Println("No active AI bridge tokens found. Run 'xora ai token create <name>' to create one.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "TOKEN LABEL\tTOKEN ID\tCREATED AT")
			for _, t := range tokens {
				label := t.Label
				if t.Revoked {
					label = t.Label + " (revoked)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", label, t.ID, t.CreatedAt.Format("2006-01-02 15:04:05"))
			}
			w.Flush()
			return nil
		},
	}
	return cmd
}

func newAITokenCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new AI bridge token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			t, err := client.CreateBridgeToken(session.AccessToken, name)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully created AI bridge token '%s'!\n", t.Label)
			fmt.Printf("Token ID: %s\n", t.ID)
			fmt.Println("\n⚠️  IMPORTANT: Copy the secret bridge token now. It will not be shown again:")
			fmt.Printf("Token: %s\n", t.Token)
			return nil
		},
	}
	return cmd
}

func newAITokenRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [token-id]",
		Short: "Revoke an AI bridge token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tokenID := args[0]

			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			err = client.RevokeBridgeToken(session.AccessToken, tokenID)
			if err != nil {
				return err
			}

			fmt.Println("AI bridge token revoked successfully.")
			return nil
		},
	}
	return cmd
}
