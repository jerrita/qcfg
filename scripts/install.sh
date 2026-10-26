#!/bin/sh
# Install the latest qcfg release. Override the target directory with QCFG_INSTALL_DIR.
set -eu

REPO=jerrita/qcfg
DIR=${QCFG_INSTALL_DIR:-$HOME/.local/bin}

case $(uname -s) in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  riscv64 | riscv64gc) arch=riscv64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [ "$os/$arch" = darwin/amd64 ]; then
  echo "unsupported platform: $os/$arch" >&2; exit 1
fi

url=https://github.com/$REPO/releases/latest/download/qcfg-$os-$arch
mkdir -p "$DIR"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
echo "downloading $url"
curl -fsSL "$url" -o "$tmp"
chmod 755 "$tmp"
mv "$tmp" "$DIR/qcfg"
echo "installed $DIR/qcfg"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "add $DIR to PATH" ;;
esac
