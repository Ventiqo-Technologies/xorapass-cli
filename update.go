package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	CLIVersion    = "v1.1.0"
	GitHubRepo    = "Ventiqo-Technologies/xorapass-cli"
	CheckInterval = 24 * time.Hour
)

type UpdateCache struct {
	LastChecked time.Time `json:"last_checked"`
	LatestVer   string    `json:"latest_ver"`
}

func getUpdateCachePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(homeDir, ".xora")
	_ = os.MkdirAll(configDir, 0700)
	return filepath.Join(configDir, "update_cache.json"), nil
}

// checkForUpdates checks GitHub Releases for a newer version asynchronously or from cache.
func checkForUpdates() string {
	cachePath, err := getUpdateCachePath()
	if err != nil {
		return ""
	}

	var cache UpdateCache
	if data, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(data, &cache)
	}

	// If checked within last 24h, return cached recommendation
	if time.Since(cache.LastChecked) < CheckInterval {
		if isNewerVersion(cache.LatestVer, CLIVersion) {
			return cache.LatestVer
		}
		return ""
	}

	// Otherwise query GitHub API with 3s timeout
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "XoraPass-CLI/"+CLIVersion)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil || rel.TagName == "" {
		return ""
	}

	// Save cache
	cache.LastChecked = time.Now()
	cache.LatestVer = rel.TagName
	if data, err := json.Marshal(cache); err == nil {
		_ = os.WriteFile(cachePath, data, 0600)
	}

	if isNewerVersion(rel.TagName, CLIVersion) {
		return rel.TagName
	}
	return ""
}

// isNewerVersion compares semver strings like "v1.1.0" vs "v1.0.0"
func isNewerVersion(latest, current string) bool {
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")
	if latest == "" || latest == current {
		return false
	}
	return latest > current
}

// newVersionCmd returns the `xora version` command.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print current XoraPass CLI version and update status",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("XoraPass CLI %s (%s/%s)\n", CLIVersion, runtime.GOOS, runtime.GOARCH)

			latest := checkForUpdates()
			if latest != "" {
				fmt.Printf("\n💡 A new release is available: %s -> %s\n", CLIVersion, latest)
				fmt.Println("   Run 'xora update-cli' to upgrade automatically.")
			} else {
				fmt.Println("You are on the latest version.")
			}
		},
	}
}

// newUpdateCLICmd returns the `xora update-cli` command.
func newUpdateCLICmd() *cobra.Command {
	return &cobra.Command{
		Use:     "update-cli",
		Aliases: []string{"self-update", "upgrade"},
		Short:   "Upgrade XoraPass CLI to the latest release",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🔍 Checking for XoraPass CLI updates...")

			client := &http.Client{Timeout: 10 * time.Second}
			req, err := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo), nil)
			if err != nil {
				return err
			}
			req.Header.Set("User-Agent", "XoraPass-CLI/"+CLIVersion)

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to fetch release metadata: %w", err)
			}
			defer resp.Body.Close()

			var rel struct {
				TagName string `json:"tag_name"`
				Assets  []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
				} `json:"assets"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
				return fmt.Errorf("failed to parse release metadata: %w", err)
			}

			if !isNewerVersion(rel.TagName, CLIVersion) {
				fmt.Printf("Already running latest version (%s).\n", CLIVersion)
				return nil
			}

			fmt.Printf("Found newer version: %s (current: %s)\n", rel.TagName, CLIVersion)

			// Determine binary asset name
			arch := runtime.GOARCH
			goos := runtime.GOOS
			assetName := fmt.Sprintf("xora-%s-%s", goos, arch)
			if goos == "windows" {
				assetName += ".exe"
			}

			var downloadURL string
			for _, asset := range rel.Assets {
				if asset.Name == assetName {
					downloadURL = asset.BrowserDownloadURL
					break
				}
			}

			if downloadURL == "" {
				return fmt.Errorf("no binary release asset found for platform %s/%s", goos, arch)
			}

			fmt.Printf("📥 Downloading %s...\n", assetName)
			dlReq, _ := http.NewRequest("GET", downloadURL, nil)
			dlReq.Header.Set("User-Agent", "XoraPass-CLI/"+CLIVersion)
			dlResp, err := client.Do(dlReq)
			if err != nil || dlResp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to download update binary")
			}
			defer dlResp.Body.Close()

			// Write temporary binary
			execPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to locate current executable path: %w", err)
			}
			execPath, _ = filepath.EvalSymlinks(execPath)

			tmpPath := execPath + ".tmp"
			tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create temp file: %w (try running with elevated permissions/sudo)", err)
			}

			_, err = io.Copy(tmpFile, dlResp.Body)
			tmpFile.Close()
			if err != nil {
				_ = os.Remove(tmpPath)
				return fmt.Errorf("failed to save download: %w", err)
			}

			// Atomic replace (on Windows, rename active binary to .old first)
			if runtime.GOOS == "windows" {
				oldPath := execPath + ".old"
				_ = os.Remove(oldPath)
				if err := os.Rename(execPath, oldPath); err != nil {
					_ = os.Remove(tmpPath)
					return fmt.Errorf("failed to replace binary: %w", err)
				}
				if err := os.Rename(tmpPath, execPath); err != nil {
					_ = os.Rename(oldPath, execPath)
					_ = os.Remove(tmpPath)
					return fmt.Errorf("failed to place new binary: %w", err)
				}
				_ = os.Remove(oldPath)
			} else {
				if err := os.Rename(tmpPath, execPath); err != nil {
					// Fallback to sudo / shell move if permission denied
					cmd := exec.Command("sudo", "mv", tmpPath, execPath)
					if err := cmd.Run(); err != nil {
						_ = os.Remove(tmpPath)
						return fmt.Errorf("failed to replace binary at %s: %w", execPath, err)
					}
				}
			}

			// Update local cache
			cachePath, _ := getUpdateCachePath()
			_ = os.WriteFile(cachePath, []byte(fmt.Sprintf(`{"last_checked":"%s","latest_ver":"%s"}`, time.Now().Format(time.RFC3339), rel.TagName)), 0600)

			fmt.Printf("🎉 Successfully updated XoraPass CLI to %s!\n", rel.TagName)
			return nil
		},
	}
}
