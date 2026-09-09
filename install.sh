#!/usr/bin/env bash
# ============================================================
# install.sh — pasang ipreal-hunter agar bisa dipanggil dari mana saja
#
#   ./install.sh
#
# Yang dilakukan:
#   1. cek python3 + dependensi (requests, dnspython, PyYAML, mmh3)
#   2. chmod +x ipreal-hunter.py
#   3. symlink /usr/local/bin/ipreal-hunter -> repo/ipreal-hunter.py
#   4. verifikasi: ipreal-hunter --self-test
# ============================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/usr/local/bin/ipreal-hunter"

info() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
fail() { echo "[-] $*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || fail "python3 tidak ditemukan"

# 1. dependensi python (install yang kurang saja)
missing=()
for mod in requests dns yaml mmh3; do
    python3 -c "import $mod" 2>/dev/null || missing+=("$mod")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    info "install dependensi yang kurang: ${missing[*]} (dari requirements.txt)"
    if ! python3 -m pip install -r "$REPO_DIR/requirements.txt" 2>/dev/null; then
        info "coba lagi dengan --break-system-packages ..."
        python3 -m pip install --break-system-packages -r "$REPO_DIR/requirements.txt" \
            || fail "pip install gagal — install manual: pip install -r requirements.txt"
    fi
else
    info "dependensi python lengkap"
fi

# 2. executable
chmod +x "$REPO_DIR/ipreal-hunter.py"

# 3. symlink sistem (butuh tulis ke /usr/local/bin)
if [[ -L "$TARGET" && "$(readlink "$TARGET")" == "$REPO_DIR/ipreal-hunter.py" ]]; then
    info "symlink sudah benar: $TARGET"
else
    if [[ -w "$(dirname "$TARGET")" ]]; then
        ln -sfn "$REPO_DIR/ipreal-hunter.py" "$TARGET"
    elif command -v sudo >/dev/null 2>&1; then
        info "perlu sudo untuk tulis ke $(dirname "$TARGET") ..."
        sudo ln -sfn "$REPO_DIR/ipreal-hunter.py" "$TARGET" \
            || fail "gagal buat symlink (coba manual: sudo ln -sfn $REPO_DIR/ipreal-hunter.py $TARGET)"
    else
        fail "tidak bisa tulis ke $(dirname "$TARGET") dan sudo tidak ada"
    fi
    info "symlink: $TARGET -> $REPO_DIR/ipreal-hunter.py"
fi

# 4. verifikasi
command -v ipreal-hunter >/dev/null 2>&1 || export PATH="$PATH:/usr/local/bin"
if ipreal-hunter --self-test 2>&1 | tail -2; then
    info "selesai — coba: ipreal-hunter --help"
else
    fail "verifikasi --self-test gagal"
fi
