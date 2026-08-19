# XoraPass CLI (`xora`)

[![Build and Release CLI](https://github.com/Ventiqo-Technologies/xorapass-cli/actions/workflows/release.yml/badge.svg)](https://github.com/Ventiqo-Technologies/xorapass-cli/actions/workflows/release.yml)
[![Version](https://img.shields.io/github/v/release/Ventiqo-Technologies/xorapass-cli?label=version&color=blue)](https://github.com/Ventiqo-Technologies/xorapass-cli/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Official command-line client for **XoraPass** — zero-knowledge enterprise password manager and AI credential firewall.

---

## 🚀 Installation

### Linux / macOS (Bash)
```bash
curl -sSL https://app.xorapass.com/install.sh | bash
```

### Windows (PowerShell)
```powershell
irm https://app.xorapass.com/install.ps1 | iex
```

---

## 🔑 Quick Start

### 1. Authenticate
```bash
# Open browser for secure SSO login
xora login

# Headless / remote machine login (Device Code activation)
xora login --no-browser
```

### 2. Basic Usage
```bash
# Check current session & active workspace
xora whoami

# List all vault credentials
xora list

# Retrieve a password value (pipe-friendly)
xora get "GitHub"

# Extract a specific field
xora get "GitHub" --field username
xora get "Stripe API Key" -f env

# Fuzzy search credentials
xora search "aws"
```

---

## 🛠️ Command Reference

| Category | Command | Description |
| :--- | :--- | :--- |
| **Auth** | `xora login` | Authenticate session via browser or device-code |
| | `xora logout` | Clear active local session |
| | `xora whoami` | Show current user email, session path, & active workspace |
| **Vault** | `xora list` | List all decrypted vault credentials |
| | `xora get <name>` | Retrieve & decrypt a specific credential |
| | `xora add` | Interactively or via flags create logins, cards, notes, SSH keys |
| | `xora edit <name>` | In-place update of existing credential fields |
| | `xora delete <name>` | Move a credential to trash |
| | `xora search <query>`| Fuzzy search across vault entries |
| **Workspaces** | `xora workspace list` | List all organization and family workspaces |
| | `xora workspace use <ws>` | Switch active workspace context |
| | `xora workspace status` | Show active workspace context |
| | `xora workspace create` | Create a new organization workspace |
| | `xora workspace saml` | View or configure SAML Single Sign-On |
| **Shared Vaults** | `xora vault list` | List shared vaults in active workspace |
| | `xora vault use <vault>`| Set active shared vault context |
| | `xora vault create` | Create a new shared vault |
| **AI Firewall** | `xora ai requests` | List pending AI credential access requests |
| | `xora ai approve <id>` | Approve an AI tool access request |
| | `xora ai deny <id>` | Deny an AI tool access request |
| | `xora ai token` | Manage AI bridge tokens (`list`, `create`, `revoke`) |
| **Data & Security**| `xora import --file <f>` | Bulk import from XoraPass CSV or JSON file |
| | `xora export --file <f>` | Export vault backup to CSV or JSON file |
| | `xora exposure` | Audit secret exposure risks and leaked key findings |
| | `xora trash` | Manage soft-deleted items (`list`, `restore`, `purge`) |
| **System** | `xora version` | Print CLI version and check for updates |
| | `xora update-cli` | Upgrade CLI binary in-place to latest release |

---

## 🛡️ Zero-Knowledge Security Model

The XoraPass CLI implements local client-side decryption:
* All vault items are encrypted using **XChaCha20-Poly1305** / **AES-256-GCM**.
* Decryption keys remain strictly on your local machine and inside memory during runtime.
* The XoraPass backend core-api server never receives or stores plaintext secret data.

---

## ⚡ Self-Updating

The CLI automatically checks GitHub Releases for new updates once every 24 hours (non-blocking). When a new version is released, run:

```bash
xora update-cli
```

---

## 📄 License
Copyright © 2026 Ventiqo Technologies. Licensed under the [MIT License](LICENSE).
