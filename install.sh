#!/usr/bin/env sh
set -eu

REPO="${HUSYNC_REPO:-YOUR_USERNAME/husync}"
VERSION="${HUSYNC_VERSION:-latest}"
INSTALL_DIR="${HUSYNC_INSTALL_DIR:-}"

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need_cmd curl
need_cmd tar

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux) PLATFORM="Linux" ;;
  Darwin) PLATFORM="macOS" ;;
  *) fail "unsupported OS: $OS (only Linux/macOS are supported by this installer)" ;;
esac

case "$ARCH" in
  x86_64|amd64) TARGET_ARCH="x86_64" ;;
  *) fail "unsupported architecture: $ARCH (only x86_64 is currently published)" ;;
esac

if [ "$VERSION" = "latest" ]; then
  TAG="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  [ -n "$TAG" ] || fail "failed to resolve latest release tag from ${REPO}"
else
  TAG="$VERSION"
fi

ASSET="husync-${PLATFORM}-${TARGET_ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

if [ -z "$INSTALL_DIR" ]; then
  if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "$INSTALL_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

log "Installing husync ${TAG} from ${REPO}"
log "Downloading: ${URL}"

curl -fL "$URL" -o "$TMP_DIR/$ASSET"
tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"

[ -f "$TMP_DIR/husync" ] || fail "invalid archive: husync binary not found"

install -m 755 "$TMP_DIR/husync" "$INSTALL_DIR/husync"

log "Installed to: $INSTALL_DIR/husync"
log "Run: husync --help"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) log "Note: add $INSTALL_DIR to your PATH if needed." ;;
esac
