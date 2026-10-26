#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=================================================="
echo "       Google Antigravity One-Click Patcher       "
echo "              Telegram: @s1lentov1                "
echo "=================================================="
echo ""
echo "Для модификации и переподписи бандлов macOS требуются права администратора."
echo ""

if [ -f "$DIR/bin/agy_patcher" ]; then
    sudo "$DIR/bin/agy_patcher" patch -A
else
    sudo python3 "$DIR/agy_patcher.py" patch -A
fi

echo ""
echo "=================================================="
read -p "Нажмите Enter, чтобы закрыть окно..."
