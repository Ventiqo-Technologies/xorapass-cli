#!/bin/env bash
set -e

# Configuration
REPO="Ventiqo-Technologies/xorapass-cli"
INSTALL_DIR="/usr/local/bin"

echo "✨ XoraPass CLI Installer"
echo "-----------------------------------"

# 1. Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux*)   PLATFORM="linux" ;;
    darwin*)  PLATFORM="darwin" ;;
    msys*|cygwin*|mingw*) PLATFORM="windows" ;;
    *)
        echo "❌ Unsupported OS: $OS"
        exit 1
        ;;
esac

# 2. Detect CPU Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  CPU="amd64" ;;
    arm64|aarch64) CPU="arm64" ;;
    *)
        echo "❌ Unsupported CPU Architecture: $ARCH"
        exit 1
        ;;
esac

# Construct binary name
BINARY_NAME="xora-${PLATFORM}-${CPU}"
if [ "$PLATFORM" = "windows" ]; then
    BINARY_NAME="${BINARY_NAME}.exe"
fi

# 3. Resolve latest release URL from GitHub API
echo "🔍 Fetching latest release metadata from GitHub..."
RELEASE_JSON=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest")
DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "$BINARY_NAME" | cut -d '"' -f 4 || true)

# Fallback: if no GitHub release assets are found (or rate-limit reached), build URL directly using latest tag name
if [ -z "$DOWNLOAD_URL" ]; then
    TAG=$(echo "$RELEASE_JSON" | grep "tag_name" | cut -d '"' -f 4 || true)
    if [ -n "$TAG" ]; then
        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${BINARY_NAME}"
    else
        # Fallback to main branch raw builds if no release exists yet
        DOWNLOAD_URL="https://raw.githubusercontent.com/${REPO}/main/dist/${BINARY_NAME}"
    fi
fi

# 4. Perform Download
TMP_BIN="/tmp/xora"
echo "📥 Downloading XoraPass CLI ($PLATFORM/$CPU)..."
curl -sSL -o "$TMP_BIN" "$DOWNLOAD_URL"

# 5. Handle Installation
echo "⚙️ Installing to $INSTALL_DIR..."
# Check if sudo permissions are needed
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_BIN" "$INSTALL_DIR/xora"
    chmod +x "$INSTALL_DIR/xora"
else
    echo "🔑 Root permissions needed. Prompting for sudo..."
    sudo mv "$TMP_BIN" "$INSTALL_DIR/xora"
    sudo chmod +x "$INSTALL_DIR/xora"
fi

echo "-----------------------------------"
echo "🎉 XoraPass CLI successfully installed!"
echo "👉 Run 'xora --help' to verify the path installation."
