#!/usr/bin/env bash
set -e

# Проверка прав администратора
if [ "$EUID" -ne 0 ]; then
    echo "[!] Для установки в /usr/local/bin требуются права суперпользователя."
    echo "    Запустите: sudo ./install.sh"
    exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/usr/local/bin/agy-patcher"

echo "[*] Установка agy-patcher в $TARGET..."

if [ -f "$DIR/bin/agy_patcher" ]; then
    cp "$DIR/bin/agy_patcher" "$TARGET"
else
    cp "$DIR/agy_patcher.py" "$TARGET"
fi

chmod +x "$TARGET"

echo "[✓] Успешно установлено!"
echo ""
echo "Теперь вы можете использовать команду agy-patcher в любом месте терминала:"
echo "  sudo agy-patcher status -A   # Проверить статус Antigravity"
echo "  sudo agy-patcher patch -A    # Применить патч"
echo "  sudo agy-patcher restore -A  # Восстановить оригиналы"
echo "  sudo agy-patcher             # Интерактивное меню"
