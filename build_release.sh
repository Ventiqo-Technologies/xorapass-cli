#!/bin/bash
set -e

# Build directory setup
BUILD_DIR="dist"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "🚀 Starting XoraPass CLI Multi-Platform Compilation..."

# Platforms configuration: "OS ARCH OUT_NAME"
PLATFORMS=(
    "linux amd64 xora-linux-amd64"
    "linux arm64 xora-linux-arm64"
    "darwin amd64 xora-darwin-amd64"
    "darwin arm64 xora-darwin-arm64"
    "windows amd64 xora-windows-amd64.exe"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    read -r GOOS GOARCH OUT_NAME <<< "$PLATFORM"
    
    echo "📦 Building for $GOOS ($GOARCH)..."
    env GOOS=$GOOS GOARCH=$GOARCH go build -o "$BUILD_DIR/$OUT_NAME"
done

echo "✅ Compilation complete. Binaries are available in 'apps/cli/$BUILD_DIR/':"
ls -lh "$BUILD_DIR"
