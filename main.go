package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
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

	rootCmd.PersistentFlags().StringVar(&apiURLFlag, "url", "https://app.xorapass.com", "XoraPass backend core-api server URL")

	var noBrowserFlag bool

	var loginCmd = &cobra.Command{
		Use:   "login",
		Short: "Authenticate with XoraPass server via web browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURLFlag)

			// Auto-detect headless/no-GUI environments (missing DISPLAY variable on non-Windows OS)
			// or if we are running in WSL as the root user (who cannot launch Windows GUI browsers)
			isRootInWSL := false
			if runtime.GOOS == "linux" && (os.Getenv("USER") == "root" || os.Getenv("LOGNAME") == "root") {
				if isWSL() {
					isRootInWSL = true
				}
			}

			if !noBrowserFlag && (runtime.GOOS != "windows" && os.Getenv("DISPLAY") == "" || isRootInWSL) {
				if isRootInWSL {
					fmt.Println("Running in WSL as root. Falling back to device code activation...")
				} else {
					fmt.Println("No GUI display environment detected. Falling back to device code activation...")
				}
				noBrowserFlag = true
			}

			if noBrowserFlag {
				// Device Code Flow
				deviceResp, err := client.RequestDeviceCode()
				if err != nil {
					return err
				}

				baseURL := strings.TrimRight(apiURLFlag, "/")
				activationURL := baseURL + "/activate?code=" + deviceResp.UserCode
				if strings.Contains(baseURL, ":8000") {
					activationURL = strings.Replace(baseURL, ":8000", ":3000", 1) + "/activate?code=" + deviceResp.UserCode
				} else if strings.Contains(baseURL, "app.xorapass.com") {
					activationURL = "https://app.xorapass.com/activate?code=" + deviceResp.UserCode
				}

				fmt.Println("To sign in, use a web browser to open the page:")
				fmt.Println("    " + activationURL)
				fmt.Println("\nAnd verify the code matches: " + deviceResp.UserCode)

				// Poll loop
				interval := time.Duration(deviceResp.Interval) * time.Second
				if interval == 0 {
					interval = 5 * time.Second
				}

				fmt.Println("\nWaiting for authorization...")
				for {
					time.Sleep(interval)
					tokenResp, err := client.PollDeviceToken(deviceResp.DeviceCode)
					if err != nil {
						continue // Network glitch, retry next loop
					}

					if tokenResp.Status == "activated" {
						encKeyBytes, err := hexDecode(tokenResp.EncryptionKey)
						if err != nil {
							// Fallback to base64
							encKeyBytes, err = base64Decode(tokenResp.EncryptionKey)
							if err != nil {
								return fmt.Errorf("failed to decode encryption key: %w", err)
							}
						}

						email := extractEmailFromToken(tokenResp.AccessToken)
						err = saveSession(email, tokenResp.AccessToken, encKeyBytes)
						if err != nil {
							return fmt.Errorf("failed to save session: %w", err)
						}

						fmt.Println("\nSuccess! Authorized CLI session stored securely.")
						return nil
					}

					if tokenResp.Error == "expired_token" {
						return fmt.Errorf("the device code has expired, please run 'xora login' again")
					}
				}
			}

			port := "8500"
			
			// 1. Construct Web Auth URL
			baseURL := strings.TrimRight(apiURLFlag, "/")
			// Replace backend api port 8000 with front-end port 3000 if running locally in dev
			webLoginURL := baseURL + "/cli-login?port=" + port
			if strings.Contains(baseURL, ":8000") {
				webLoginURL = strings.Replace(baseURL, ":8000", ":3000", 1) + "/cli-login?port=" + port
			} else if strings.Contains(baseURL, "app.xorapass.com") {
				// Live production URL mapping
				webLoginURL = "https://app.xorapass.com/cli-login?port=" + port
			}

			fmt.Println("Starting local callback server on port " + port + "...")
			fmt.Println("Opening browser for secure authentication...")
			
			// 2. Start callback listener and launch browser
			openBrowser(webLoginURL)

			token, encKey, err := startSSOServer(port)
			if err != nil {
				return fmt.Errorf("web login failed: %w", err)
			}

			// 3. Cache session (CLI extracts email from token claims or uses generic)
			email := extractEmailFromToken(token)
			err = saveSession(email, token, encKey)
			if err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}

			fmt.Println("\nSuccess! Authorized CLI session stored securely.")
			return nil
		},
	}

	loginCmd.Flags().BoolVar(&noBrowserFlag, "no-browser", false, "Authenticate on a remote machine without opening a local browser")
	rootCmd.PersistentFlags().StringVarP(&formatFlag, "format", "f", "text", "output format (text, json, env)")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(newLogoutCmd())
	rootCmd.AddCommand(newWhoamiCmd())
	rootCmd.AddCommand(newListCmd())
	rootCmd.AddCommand(newGetCmd())
	rootCmd.AddCommand(newSearchCmd())
	rootCmd.AddCommand(newAddCmd())
	rootCmd.AddCommand(newDeleteCmd())
	rootCmd.AddCommand(newWorkspaceCmd())
	rootCmd.AddCommand(newVaultMgmtCmd())
	rootCmd.AddCommand(newAICmd())
	rootCmd.AddCommand(newImportCmd())
	rootCmd.AddCommand(newTrashCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// isWSL checks if the application is running inside Windows Subsystem for Linux
func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Check environment variable
	if _, wsl := os.LookupEnv("WSL_DISTRO_NAME"); wsl {
		return true
	}
	// Fallback: check /proc/version which contains "microsoft" or "wsl" on WSL distros
	versionBytes, err := os.ReadFile("/proc/version")
	if err == nil {
		versionStr := strings.ToLower(string(versionBytes))
		if strings.Contains(versionStr, "microsoft") || strings.Contains(versionStr, "wsl") {
			return true
		}
	}
	return false
}

