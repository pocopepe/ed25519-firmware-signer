#!/usr/bin/env sh
set -eu

REPO="pocopepe/ed25519-firmware-signer"
BIN_NAME="binsign"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
fi

if [ -z "$VERSION" ]; then
    echo "Failed to resolve the latest release tag."
    exit 1
fi

os_name=$(uname -s)
arch_name=$(uname -m)

case "$os_name:$arch_name" in
    Linux:x86_64)
        target="x86_64-unknown-linux-gnu"
        use_deb=1
        ;;
    Linux:aarch64|Linux:arm64)
        target="aarch64-unknown-linux-gnu"
        use_deb=0
        ;;
    Darwin:x86_64)
        target="x86_64-apple-darwin"
        use_deb=0
        ;;
    Darwin:arm64|Darwin:aarch64)
        target="aarch64-apple-darwin"
        use_deb=0
        ;;
    *)
        echo "Unsupported platform: $os_name $arch_name"
        exit 1
        ;;
esac


work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT INT TERM
# Try .deb package first on Linux x86_64 if sudo is available
if [ "$use_deb" = "1" ] && command -v sudo >/dev/null 2>&1; then
    deb_name="binsign_${VERSION#v}_amd64.deb"
    deb_url="https://github.com/$REPO/releases/download/$VERSION/$deb_name"
    
    if curl -fsSL --head "$deb_url" >/dev/null 2>&1; then
        echo "Installing .deb package: $deb_name"
        curl -fsSL "$deb_url" -o "$work_dir/$deb_name"
        sudo dpkg -i "$work_dir/$deb_name"
        echo "Installed $BIN_NAME via .deb package"
        exit 0
    fi
fi

# Fall back to binary installation
asset_name="$BIN_NAME-$VERSION-$target"
download_url="https://github.com/$REPO/releases/download/$VERSION/$asset_name"


curl -fsSL "$download_url" -o "$work_dir/$BIN_NAME"
chmod 755 "$work_dir/$BIN_NAME"

if [ ! -w "$INSTALL_DIR" ] && [ "$(id -u)" -ne 0 ]; then
    INSTALL_DIR="${HOME}/.local/bin"
fi

mkdir -p "$INSTALL_DIR"
install -m 755 "$work_dir/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

echo "Installed $BIN_NAME to $INSTALL_DIR/$BIN_NAME"
