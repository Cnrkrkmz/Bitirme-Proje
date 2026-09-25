#!/usr/bin/env bash
# Faz 0 icin gereken arac zincirini kurar (Ubuntu/Debian).
set -euo pipefail

SUDO=""
[[ $EUID -ne 0 ]] && SUDO=sudo

echo "==> apt paketleri"
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
	clang llvm libbpf-dev libelf-dev zlib1g-dev \
	build-essential pkg-config golang-go

# bpftool cogu dagitimda linux-tools icinde; bulunmazsa zararsiz gec.
if ! command -v bpftool >/dev/null && [[ ! -x /usr/sbin/bpftool ]]; then
	echo "==> bpftool"
	$SUDO apt-get install -y --no-install-recommends \
		linux-tools-common "linux-tools-$(uname -r)" || \
		echo "UYARI: bpftool kurulamadi; vmlinux.h uretemezsiniz."
fi

# apt'taki Go cok eskiyse (go.mod 1.22 istiyor) resmi tarball'a dus.
GO_BIN=$(command -v go || echo /usr/local/go/bin/go)
if ! "$GO_BIN" version >/dev/null 2>&1 || \
   [[ $("$GO_BIN" env GOVERSION 2>/dev/null | sed 's/go1\.\([0-9]*\).*/\1/') -lt 22 ]]; then
	GO_VERSION=1.23.4
	case "$(uname -m)" in
		x86_64)  GO_ARCH=amd64 ;;
		aarch64) GO_ARCH=arm64 ;;
		*) echo "desteklenmeyen mimari: $(uname -m)"; exit 1 ;;
	esac
	echo "==> Go ${GO_VERSION} (${GO_ARCH})"
	tmp=$(mktemp -d)
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$tmp/go.tgz"
	$SUDO rm -rf /usr/local/go
	$SUDO tar -C /usr/local -xzf "$tmp/go.tgz"
	rm -rf "$tmp"
	echo "   PATH'e ekleyin:  export PATH=\$PATH:/usr/local/go/bin"
fi

echo "==> dogrulama"
for t in clang llvm-strip; do
	printf '  %-12s ' "$t"
	command -v "$t" >/dev/null && echo OK || echo EKSIK
done
printf '  %-12s ' bpftool
(command -v bpftool >/dev/null || [[ -x /usr/sbin/bpftool ]]) && echo OK || echo EKSIK
printf '  %-12s ' go
(command -v go >/dev/null || [[ -x /usr/local/go/bin/go ]]) && echo OK || echo EKSIK
printf '  %-12s ' BTF
[[ -r /sys/kernel/btf/vmlinux ]] && echo OK || echo "EKSIK - CO-RE calismaz"
