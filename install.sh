#!/bin/sh
# grokpatrol installer.
#
#   curl -fsSL https://raw.githubusercontent.com/optimuslabs-io/grokpatrol/main/install.sh | sh
#
# Downloads the release binary for this OS/architecture, verifies it against
# the release's SHA256SUMS, and installs it as `grokpatrol` on your PATH.
# Reading this script before piping it to sh is encouraged -- that is why it
# lives at a stable URL in the repository root.
#
# Environment overrides:
#   GROKPATROL_VERSION      install a specific tag (e.g. v0.1.0) instead of latest
#   GROKPATROL_INSTALL_DIR  install directory (default: ~/.local/bin if already
#                           on PATH, otherwise /usr/local/bin)
#
# This script never invokes sudo. If the install directory is not writable it
# tells you how to re-run, and exits.
#
# What the checksum buys, honestly stated: SHA256SUMS is published alongside
# the binaries it describes, so verifying it protects against corrupted or
# truncated downloads -- not against a compromised release. For proof that a
# binary was built by this repository's release workflow, verify its sigstore
# provenance instead:
#   gh attestation verify <binary> -R optimuslabs-io/grokpatrol

set -eu

REPO="optimuslabs-io/grokpatrol"

# All progress goes to stderr; stdout stays clean.
note() { printf '%s\n' "$*" >&2; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

main() {
    command -v curl >/dev/null 2>&1 || fail "curl is required"

    case "$(uname -s)" in
        Darwin) os=darwin ;;
        Linux)  os=linux ;;
        *) fail "unsupported OS '$(uname -s)' -- download a binary from https://github.com/$REPO/releases (Windows binaries are published there)" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)  arch=amd64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) fail "unsupported architecture '$(uname -m)'" ;;
    esac

    # Resolve the tag to install. `releases/latest` redirects to
    # `releases/tag/vX.Y.Z`, so the final URL's last path segment is the tag --
    # no API call, no rate limit, no JSON parsing.
    if [ -n "${GROKPATROL_VERSION:-}" ]; then
        tag="$GROKPATROL_VERSION"
    elif [ -n "${GROKPATROL_BASE_URL:-}" ]; then
        fail "GROKPATROL_BASE_URL requires GROKPATROL_VERSION"
    else
        tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")"
        tag="${tag##*/}"
        case "$tag" in
            v[0-9]*) ;;
            latest) fail "no releases published yet at https://github.com/$REPO/releases" ;;
            *) fail "could not determine the latest release tag (got '$tag')" ;;
        esac
    fi

    # Release assets are raw binaries named grokpatrol_<tag>_<os>_<arch>.
    asset="grokpatrol_${tag}_${os}_${arch}"
    base="${GROKPATROL_BASE_URL:-https://github.com/$REPO/releases/download/$tag}"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    note "downloading $asset ($tag) ..."
    curl -fsSL -o "$tmp/$asset" "$base/$asset" \
        || fail "download failed: $base/$asset"
    curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
        || fail "download failed: $base/SHA256SUMS"

    # Verify before installing, and never install unverified: if neither
    # checksum tool exists, that is an error, not a warning.
    note "verifying checksum ..."
    if command -v sha256sum >/dev/null 2>&1; then
        sumtool="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sumtool="shasum -a 256"
    else
        fail "neither sha256sum nor shasum found; refusing to install unverified"
    fi
    # SHA256SUMS lists every platform's binary; keep only the line for ours.
    grep " $asset\$" "$tmp/SHA256SUMS" > "$tmp/expected.sum" \
        || fail "$asset is not listed in SHA256SUMS"
    ( cd "$tmp" && $sumtool -c expected.sum >/dev/null ) \
        || fail "checksum mismatch for $asset -- refusing to install"

    # Pick the install directory. ~/.local/bin only qualifies if it is already
    # on PATH (stock macOS does not have it there, and installing somewhere the
    # shell will not look ends in "command not found").
    if [ -n "${GROKPATROL_INSTALL_DIR:-}" ]; then
        dir="$GROKPATROL_INSTALL_DIR"
    else
        case ":$PATH:" in
            *":$HOME/.local/bin:"*) dir="$HOME/.local/bin" ;;
            *) dir="/usr/local/bin" ;;
        esac
    fi

    if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
        note "install.sh: $dir is not a writable directory."
        note "re-run with a directory you can write to:"
        note "  GROKPATROL_INSTALL_DIR=\$HOME/bin sh install.sh"
        note "or, if $dir is where you want it, re-run the installer with sudo."
        exit 1
    fi

    install -m 0755 "$tmp/$asset" "$dir/grokpatrol"

    note "installed $dir/grokpatrol"
    "$dir/grokpatrol" --version >&2
}

# Nothing executes until the whole script has arrived: a connection that drops
# mid-download leaves a truncated main() that parses but never runs.
main "$@"
