#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт кроссплатформенной сборки agy_patcher.
Поддерживает сборку:
  - Нативного бинарника через PyInstaller (Windows .exe / Linux ELF / macOS Mach-O)
  - Универсального исполняемого zipapp (.pyz / executable script)
"""
import os
import platform
import shutil
import subprocess
import sys
import zipapp
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_FILE = ROOT_DIR / "agy_patcher.py"
BIN_DIR = ROOT_DIR / "bin"
DIST_DIR = ROOT_DIR / "dist"
BUILD_DIR = ROOT_DIR / "build"


def log(msg: str):
    print(f"[*] {msg}", flush=True)


def build_zipapp():
    log("Сборка универсального zipapp...")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    staging = ROOT_DIR / "_zipapp_staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    shutil.copy2(SRC_FILE, staging / "__main__.py")

    target = BIN_DIR / "agy_patcher"
    zipapp.create_archive(
        source=staging,
        target=target,
        interpreter="/usr/bin/env python3",
    )
    shutil.rmtree(staging)

    # На Unix делаем файл исполняемым (+x)
    if platform.system() != "Windows":
        target.chmod(target.stat().st_mode | 0o111)

    log(f"Универсальный zipapp создан: {target} ({target.stat().st_size} байт)")


def build_pyinstaller():
    log(f"Сборка нативного бинарника для платформы {platform.system()} ({platform.machine()})...")

    # Проверка наличия PyInstaller
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        log("PyInstaller не установлен в текущем окружении. Устанавливаю via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--onefile",
        "--name",
        "agy_patcher",
        str(SRC_FILE),
    ]

    subprocess.check_call(cmd, cwd=str(ROOT_DIR))

    # Копируем результат в bin/
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    exe_name = "agy_patcher.exe" if platform.system() == "Windows" else "agy_patcher"
    src_bin = DIST_DIR / exe_name

    if src_bin.exists():
        dst_bin = BIN_DIR / exe_name
        shutil.copy2(src_bin, dst_bin)
        log(f"Нативный бинарник успешно собран и скопирован: {dst_bin} ({dst_bin.stat().st_size} байт)")
    else:
        log(f"Предупреждение: {src_bin} не найден после сборки.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Сборщик agy_patcher")
    parser.add_argument("--zipapp-only", action="store_true", help="Собрать только универсальный zipapp")
    parser.add_argument("--native-only", action="store_true", help="Собрать только нативный бинарник (PyInstaller)")
    parser.add_argument("--clean", action="store_true", help="Очистить временные папки build/ и dist/")
    args = parser.parse_args()

    if args.clean:
        log("Очистка временных директорий...")
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
        shutil.rmtree(DIST_DIR, ignore_errors=True)
        spec = ROOT_DIR / "agy_patcher.spec"
        if spec.exists():
            spec.unlink()
        log("Очистка завершена.")
        return

    if args.zipapp_only:
        build_zipapp()
    elif args.native_only:
        build_pyinstaller()
    else:
        build_zipapp()
        build_pyinstaller()

    log("Сборка успешно завершена!")


if __name__ == "__main__":
    main()
