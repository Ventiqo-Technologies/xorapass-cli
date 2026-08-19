package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// csvColumn indices for XoraPass CSV export format
// label, category, username, value, url, notes,
// cardholderName, cardNumber, expiryDate, cvv,
// privateKey, publicKey, passphrase, organization
const (
	colLabel          = 0
	colCategory       = 1
	colUsername       = 2
	colValue          = 3
	colURL            = 4
	colNotes          = 5
	colCardholderName = 6
	colCardNumber     = 7
	colExpiryDate     = 8
	colCVV            = 9
	colPrivateKey     = 10
	colPublicKey      = 11
	colPassphrase     = 12
	colOrganization   = 13
)

func newImportCmd() *cobra.Command {
	var fileFlag string
	var dryRunFlag bool

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import vault entries from an XoraPass CSV or JSON export file",
		Long: `Import credentials from an XoraPass export file (.csv or .json).

Examples:
  xora import --file xorapass_export.csv
  xora import --file xorapass_export.json
  xora import --file xorapass_export.csv --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fileFlag == "" {
				return fmt.Errorf("--file is required. Example: xora import --file xorapass_export.csv")
			}

			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			f, err := os.Open(fileFlag)
			if err != nil {
				return fmt.Errorf("failed to open file '%s': %w", fileFlag, err)
			}
			defer f.Close()

			var items []DecryptedVaultItem

			if strings.HasSuffix(strings.ToLower(fileFlag), ".json") {
				items, err = parseJSONImport(f)
			} else {
				items, err = parseCSVImport(f)
			}
			if err != nil {
				return err
			}

			if len(items) == 0 {
				fmt.Println("No entries found in the import file.")
				return nil
			}

			fmt.Printf("Found %d entries to import.\n", len(items))

			if dryRunFlag {
				fmt.Println("\n--- DRY RUN --- (no changes made)")
				for i, item := range items {
					fmt.Printf("  [%d] %-30s  category=%-8s  username=%s\n", i+1, item.Label, item.Category, item.Username)
				}
				return nil
			}

			client := NewAPIClient(apiURLFlag)
			imported := 0
			failed := 0

			for _, item := range items {
				plaintext, err := json.Marshal(item)
				if err != nil {
					fmt.Printf("  ⚠️  Skipping '%s': failed to serialize: %v\n", item.Label, err)
					failed++
					continue
				}

				payload, nonce, err := encryptPayload(string(plaintext), encKey)
				if err != nil {
					fmt.Printf("  ⚠️  Skipping '%s': encryption failed: %v\n", item.Label, err)
					failed++
					continue
				}

				err = client.CreateVaultEntry(session.AccessToken, session.ActiveWorkspaceID, session.ActiveVaultID, payload, nonce)
				if err != nil {
					fmt.Printf("  ⚠️  Skipping '%s': API error: %v\n", item.Label, err)
					failed++
					continue
				}

				fmt.Printf("  ✓  Imported: %s [%s]\n", item.Label, item.Category)
				imported++
			}

			fmt.Printf("\nImport complete: %d imported, %d failed.\n", imported, failed)
			return nil
		},
	}

	cmd.Flags().StringVar(&fileFlag, "file", "", "Path to the XoraPass export file (.csv or .json)")
	cmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Preview what would be imported without making any changes")
	return cmd
}

// ---- EXPORT COMMAND ----

func newExportCmd() *cobra.Command {
	var fileFlag string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all vault entries to a CSV or JSON file",
		Long: `Export all decrypted vault credentials to a .csv or .json file.

Examples:
  xora export --file my_vault_backup.csv
  xora export --file my_vault_backup.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fileFlag == "" {
				return fmt.Errorf("--file is required. Example: xora export --file vault_backup.csv")
			}

			session, encKey, err := decodeSession()
			if err != nil {
				return err
			}

			items, _, err := decryptAll(session, encKey, apiURLFlag)
			if err != nil {
				return err
			}

			if len(items) == 0 {
				fmt.Println("No entries to export.")
				return nil
			}

			f, err := os.Create(fileFlag)
			if err != nil {
				return fmt.Errorf("failed to create export file '%s': %w", fileFlag, err)
			}
			defer f.Close()

			if strings.HasSuffix(strings.ToLower(fileFlag), ".json") {
				data, err := json.MarshalIndent(items, "", "  ")
				if err != nil {
					return err
				}
				_, err = f.Write(data)
				if err != nil {
					return err
				}
			} else {
				writer := csv.NewWriter(f)
				// Write standard XoraPass CSV headers
				header := []string{
					"label", "category", "username", "value", "url", "notes",
					"cardholderName", "cardNumber", "expiryDate", "cvv",
					"privateKey", "publicKey", "passphrase", "organization",
				}
				if err := writer.Write(header); err != nil {
					return err
				}

				for _, item := range items {
					record := []string{
						item.Label, item.Category, item.Username, item.Value, item.URL, item.Notes,
						item.CardholderName, item.CardNumber, item.ExpiryDate, item.Cvv,
						item.PrivateKey, item.PublicKey, item.Passphrase, item.Organization,
					}
					if err := writer.Write(record); err != nil {
						return err
					}
				}
				writer.Flush()
			}

			fmt.Printf("Successfully exported %d vault entries to '%s'.\n", len(items), fileFlag)
			return nil
		},
	}

	cmd.Flags().StringVar(&fileFlag, "file", "", "Output filepath for export (.csv or .json)")
	return cmd
}

// ---- EXPOSURE / AUDIT COMMAND ----

func newExposureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "exposure",
		Aliases: []string{"exposures", "audit"},
		Short:   "Check secret exposure risks and leaked credential findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, _, err := decodeSession()
			if err != nil {
				return err
			}

			client := NewAPIClient(apiURLFlag)
			summary, err := client.SummarizeExposures(session.AccessToken)
			if err != nil {
				return err
			}

			findings, err := client.FetchExposures(session.AccessToken)
			if err != nil {
				return err
			}

			if formatFlag == "json" {
				res := map[string]interface{}{
					"summary":  summary,
					"findings": findings,
				}
				data, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("=== Secret Exposure Risk Summary ===")
			fmt.Printf("Total Findings: %d | Active Risk: %d | Critical: %d | High: %d | Medium: %d | Low: %d\n\n",
				summary.TotalFindings, summary.ActiveExposures, summary.Critical, summary.High, summary.Medium, summary.Low)

			if len(findings) == 0 {
				fmt.Println("No secret exposure findings detected. All vault credentials are safe!")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "FINDING ID\tSECRET TYPE\tSEVERITY\tSOURCE\tSTATUS\tDESTINATION")
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.SecretType, f.Severity, f.Source, f.Status, f.Destination)
			}
			w.Flush()
			return nil
		},
	}

	return cmd
}

// parseCSVImport reads an XoraPass CSV export and returns DecryptedVaultItems.
// Column order must match the XoraPass export format.
func parseCSVImport(r io.Reader) ([]DecryptedVaultItem, error) {
	reader := csv.NewReader(r)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // allow variable columns

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV file has no data rows (expected at least a header + 1 data row)")
	}

	// Build header index map (case-insensitive) for flexible column ordering
	headers := make(map[string]int)
	for i, h := range records[0] {
		headers[strings.ToLower(strings.TrimSpace(h))] = i
	}

	// Helper to safely get a field by header name, falling back to positional index
	get := func(row []string, name string, positional int) string {
		if idx, ok := headers[strings.ToLower(name)]; ok && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		if positional >= 0 && positional < len(row) {
			return strings.TrimSpace(row[positional])
		}
		return ""
	}

	var items []DecryptedVaultItem
	for rowNum, row := range records[1:] {
		label := get(row, "label", colLabel)
		if label == "" || strings.EqualFold(label, "label") {
			continue // skip blank rows or duplicate headers
		}

		category := strings.ToLower(get(row, "category", colCategory))
		if category == "" {
			category = "login"
		}

		// Format card number with spaces every 4 digits
		rawCard := get(row, "cardnumber", colCardNumber)
		formattedCard := formatCardNumber(rawCard)

		item := DecryptedVaultItem{
			Label:          label,
			Category:       category,
			Username:       get(row, "username", colUsername),
			Value:          get(row, "value", colValue),
			URL:            get(row, "url", colURL),
			Notes:          get(row, "notes", colNotes),
			Organization:   get(row, "organization", colOrganization),
			CardholderName: get(row, "cardholdername", colCardholderName),
			CardNumber:     formattedCard,
			ExpiryDate:     get(row, "expirydate", colExpiryDate),
			Cvv:            get(row, "cvv", colCVV),
			PrivateKey:     get(row, "privatekey", colPrivateKey),
			PublicKey:      get(row, "publickey", colPublicKey),
			Passphrase:     get(row, "passphrase", colPassphrase),
		}

		_ = rowNum
		items = append(items, item)
	}

	return items, nil
}

// parseJSONImport reads an XoraPass JSON export and returns DecryptedVaultItems.
func parseJSONImport(r io.Reader) ([]DecryptedVaultItem, error) {
	var raw []map[string]string
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var items []DecryptedVaultItem
	for _, m := range raw {
		label := strings.TrimSpace(m["label"])
		if label == "" {
			continue
		}
		category := strings.ToLower(strings.TrimSpace(m["category"]))
		if category == "" {
			category = "login"
		}

		items = append(items, DecryptedVaultItem{
			Label:          label,
			Category:       category,
			Username:       m["username"],
			Value:          m["value"],
			URL:            m["url"],
			Notes:          m["notes"],
			Organization:   m["organization"],
			CardholderName: m["cardholderName"],
			CardNumber:     formatCardNumber(m["cardNumber"]),
			ExpiryDate:     m["expiryDate"],
			Cvv:            m["cvv"],
			PrivateKey:     m["privateKey"],
			PublicKey:      m["publicKey"],
			Passphrase:     m["passphrase"],
		})
	}
	return items, nil
}

// formatCardNumber strips non-digits and re-formats card number as "XXXX XXXX XXXX XXXX"
func formatCardNumber(raw string) string {
	if raw == "" {
		return ""
	}
	var digits strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	clean := digits.String()
	if clean == "" {
		return raw // not a standard card number, keep as-is
	}
	var formatted strings.Builder
	for i, r := range clean {
		if i > 0 && i%4 == 0 {
			formatted.WriteRune(' ')
		}
		formatted.WriteRune(r)
	}
	return formatted.String()
}
