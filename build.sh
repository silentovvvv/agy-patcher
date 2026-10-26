#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo "[*] Building agy_patcher..."
python3 build.py
echo "[OK] Done! Binaries are in bin/"
