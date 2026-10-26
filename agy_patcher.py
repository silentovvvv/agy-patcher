#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agy_patcher — безопасный сигнатурный патчер для PE / ELF / Mach-O (Windows, Linux, macOS).

Только стандартная библиотека Python 3.8+. Конкретных сигнатур в скрипте НЕТ:
оригинальные и заменяющие байты вы задаёте сами (в CLI или в JSON-конфиге).

Гарантии:
  * Поиск строго в исполняемых секциях (PE: MEM_EXECUTE; ELF: SHF_EXECINSTR /
    PT_LOAD PF_X; Mach-O: секции с кодом в сегментах VM_PROT_EXECUTE);
  * Поддержка Universal/Fat Mach-O: поиск с учётом архитектурных срезов (x86_64, arm64 и др.);
  * Контроль однозначности: 0 или >1 совпадений в целевом срезе = ошибка, файл не трогается;
  * Резервная копия <файл>.agybak перед записью (проверка размера, SHA-256 и сигнатуры);
  * Пост-верификация: проверка каждого окна, размера, SHA-256 всего файла и повторный анализ;
  * Транзакционность: при ошибке, Ctrl+C или SIGTERM выполняется полный откат;
  * Windows: автоматический пересчёт PE CheckSum и предупреждение о подписи Authenticode;
  * Права доступа: временное снятие флага Read-Only / chmod +w с последующим восстановлением;
  * macOS: снимок и восстановление подписи .app (.agysignbak), автоматическая ad-hoc переподпись;
  * Режим --dry-run: безопасный предварительный просмотр изменений с Hex-Diff.

Формат конфига (JSON):
  {
    "patches": [
      {
        "name": "Описание патча (опционально)",
        "file": "путь/к/бинарнику",
        "arch": "x86_64", // опционально для fat Mach-O
        "original": "48 8B ?? 05 00 00 00",
        "patched":  "48 8B ?? 90 90 90 90"
      }
    ]
  }
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import plistlib
import re
import shutil
import signal
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

__version__ = "1.1.0"

BAK_SUFFIX = ".agybak"
SIGN_SUFFIX = ".agysignbak"
IS_DARWIN = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"
MIN_CONCRETE = 4  # минимум заданных (не ??) байт в паттерне
BUNDLE_EXT = (".app", ".framework", ".xpc", ".appex", ".plugin", ".bundle")

# Известные cputype Mach-O
MACH_CPU_TYPES = {
    0x00000007: "i386",
    0x01000007: "x86_64",
    0x0000000C: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}


class PatchError(Exception):
    """Исключение при ошибке проверки или применения патча."""
    pass


# --------------------------------------------------------------------------- #
# Форматирование и вывод
# --------------------------------------------------------------------------- #
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")


def colorize(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def c_ok(s: str) -> str:
    return colorize(s, "32")


def c_err(s: str) -> str:
    return colorize(s, "31")


def c_warn(s: str) -> str:
    return colorize(s, "33")


def c_cyan(s: str) -> str:
    return colorize(s, "36")


def c_bold(s: str) -> str:
    return colorize(s, "1")


# Настройка безопасной кодировки консоли
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def log(msg: str = "") -> None:
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        print(msg.encode(enc, errors="replace").decode(enc), flush=True)


def format_hex_diff(offset: int, before: bytes, target: bytes) -> str:
    b_hex = " ".join(f"{b:02X}" for b in before)
    t_hex = " ".join(f"{t:02X}" for t in target)
    diff = " ".join("^^" if b != t else "  " for b, t in zip(before, target))
    return (
        f"    {c_cyan('Смещение:')} 0x{offset:08X}\n"
        f"    {c_cyan('Было:')}     {b_hex}\n"
        f"    {c_cyan('Стало:')}    {t_hex}\n"
        f"    {c_cyan('Разница:')}  {c_warn(diff)}"
    )


# --------------------------------------------------------------------------- #
# Паттерны и описания задач
# --------------------------------------------------------------------------- #
class Pattern:
    def __init__(self, text: str):
        t = re.sub(r"[\s,]+", "", text)
        if t.lower().startswith("0x"):
            t = t[2:]
        if not t or len(t) % 2 or not re.fullmatch(r"(?:[0-9a-fA-F]{2}|\?\?)+", t):
            raise PatchError(f"некорректный hex-паттерн: {text!r}")
        self.tokens: List[Optional[int]] = [
            None if t[i:i + 2] == "??" else int(t[i:i + 2], 16) for i in range(0, len(t), 2)
        ]
        if sum(x is not None for x in self.tokens) < MIN_CONCRETE:
            raise PatchError(f"в паттерне должно быть минимум {MIN_CONCRETE} заданных байта")
        self.length = len(self.tokens)
        self.regex = re.compile(
            b"".join(b"." if x is None else re.escape(bytes([x])) for x in self.tokens), re.DOTALL
        )

    def matches(self, data: bytes) -> bool:
        return len(data) == self.length and all(t is None or t == b for t, b in zip(self.tokens, data))


@dataclass
class Job:
    path: str
    original: Pattern
    patched: Pattern
    name: Optional[str] = None
    arch: Optional[str] = None

    def __post_init__(self):
        o, p = self.original, self.patched
        if o.length != p.length:
            raise PatchError("original и patched должны быть одной длины")
        if not any(a is not None and b is not None and a != b for a, b in zip(o.tokens, p.tokens)):
            raise PatchError("нужна хотя бы одна позиция, где original и patched заданы и различаются")

    def target_window(self, window: bytes) -> bytes:
        return bytes(b if t is None else t for t, b in zip(self.patched.tokens, window))


# --------------------------------------------------------------------------- #
# Парсеры форматов файлов
# --------------------------------------------------------------------------- #
def u(fmt: str, buf: Union[bytes, mmap.mmap], off: int):
    try:
        return struct.unpack_from(fmt, buf, off)
    except (struct.error, ValueError):
        raise PatchError("повреждённый или обрезанный заголовок")


@dataclass
class Slice:
    name: str
    ranges: List[Tuple[int, int]]
    cputype: Optional[int] = None


def merge_ranges(ranges: List[Tuple[int, int]], size: int) -> List[Tuple[int, int]]:
    rs = sorted((max(0, s), min(e, size)) for s, e in ranges)
    out: List[Tuple[int, int]] = []
    for s, e in rs:
        if s >= e:
            continue
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def pe_ranges(m: Union[bytes, mmap.mmap]) -> Tuple[List[Slice], Dict[str, Any]]:
    size = len(m)
    (lfanew,) = u("<I", m, 0x3C)
    if bytes(m[lfanew:lfanew + 4]) != b"PE\0\0":
        raise PatchError("PE: нет сигнатуры PE\\0\\0")
    (nsec,) = u("<H", m, lfanew + 6)
    (optsz,) = u("<H", m, lfanew + 20)
    (magic,) = u("<H", m, lfanew + 24)
    table = lfanew + 24 + optsz
    raw_ranges = []
    for i in range(nsec):
        o = table + 40 * i
        vsize, _vaddr, rawsz, rawptr = u("<IIII", m, o + 8)
        (chars,) = u("<I", m, o + 36)
        if chars & 0x20000000 and rawptr and rawsz:  # IMAGE_SCN_MEM_EXECUTE
            n = min(rawsz, vsize) if vsize else rawsz
            raw_ranges.append((rawptr, min(rawptr + n, size)))

    # Информация об Authenticode
    has_authenticode = False
    sec_dir_off = lfanew + 24 + (144 if magic == 0x20B else 128)
    if optsz >= (144 + 8 if magic == 0x20B else 128 + 8):
        sec_vaddr, sec_size = u("<II", m, sec_dir_off)
        if sec_size > 0:
            has_authenticode = True

    extra = {
        "lfanew": lfanew,
        "magic": magic,
        "has_authenticode": has_authenticode,
        "sec_dir_off": sec_dir_off,
    }
    return [Slice(name="main", ranges=merge_ranges(raw_ranges, size))], extra


def elf_ranges(m: Union[bytes, mmap.mmap]) -> Tuple[List[Slice], Dict[str, Any]]:
    size = len(m)
    cls, data = m[4], m[5]
    if cls not in (1, 2) or data not in (1, 2):
        raise PatchError("ELF: неизвестный класс/порядок байт")
    e = "<" if data == 1 else ">"
    if cls == 2:
        phoff, shoff = u(e + "QQ", m, 0x20)
        phentsize, phnum, shentsize, shnum = u(e + "HHHH", m, 0x36)
    else:
        phoff, shoff = u(e + "II", m, 0x1C)
        phentsize, phnum, shentsize, shnum = u(e + "HHHH", m, 0x2A)

    raw_ranges: List[Tuple[int, int]] = []
    if shoff and shnum:
        for i in range(shnum):
            o = shoff + i * shentsize
            if cls == 2:
                _n, typ, flags, _a, off, sz = u(e + "IIQQQQ", m, o)
            else:
                _n, typ, flags, _a, off, sz = u(e + "IIIIII", m, o)
            if flags & 0x4 and typ != 8 and sz:  # SHF_EXECINSTR, не SHT_NOBITS
                raw_ranges.append((off, min(off + sz, size)))
    if not raw_ranges and phoff and phnum:  # нет таблицы секций — берём исполняемые PT_LOAD
        for i in range(phnum):
            o = phoff + i * phentsize
            if cls == 2:
                typ, flags, off, _v, _p, fsz = u(e + "IIQQQQ", m, o)
            else:
                typ, off, _v, _p, fsz, _ms, flags = u(e + "IIIIIII", m, o)
            if typ == 1 and flags & 1 and fsz:
                raw_ranges.append((off, min(off + fsz, size)))
    return [Slice(name="main", ranges=merge_ranges(raw_ranges, size))], {}


_MACHO_THIN = {
    0xFEEDFACE: ("<", False), 0xFEEDFACF: ("<", True),
    0xCEFAEDFE: (">", False), 0xCFFAEDFE: (">", True),
}


def macho_thin_ranges(m: Union[bytes, mmap.mmap], base: int, end: int) -> List[Tuple[int, int]]:
    (magic,) = u("<I", m, base)
    if magic not in _MACHO_THIN:
        raise PatchError("Mach-O: неизвестная magic")
    e, is64 = _MACHO_THIN[magic]
    ncmds, _sizeofcmds = u(e + "II", m, base + 16)
    off = base + (32 if is64 else 28)
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = u(e + "II", m, off)
        if cmdsize < 8:
            raise PatchError("Mach-O: некорректный load command")
        if cmd in (0x1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
            if cmd == 0x19:
                initprot, nsects = u(e + "II", m, off + 60)
                sec0, secsz = off + 72, 80
            else:
                initprot, nsects = u(e + "II", m, off + 44)
                sec0, secsz = off + 56, 68
            if initprot & 0x4:  # VM_PROT_EXECUTE
                for i in range(nsects):
                    so = sec0 + i * secsz
                    _addr, size, offset = (
                        u(e + "QQI", m, so + 32) if cmd == 0x19 else u(e + "III", m, so + 32)
                    )
                    (flags,) = u(e + "I", m, so + (64 if cmd == 0x19 else 56))
                    typ = flags & 0xFF
                    if (flags & 0x80000400) and typ not in (0x1, 0xC, 0x12) and offset and size:
                        out.append((base + offset, min(base + offset + size, end)))
        off += cmdsize
    return out


def macho_ranges(m: Union[bytes, mmap.mmap]) -> Tuple[List[Slice], Dict[str, Any]]:
    size = len(m)
    (magic,) = u(">I", m, 0)
    if magic in (0xCAFEBABE, 0xCAFEBABF):  # Universal / Fat
        is64 = magic == 0xCAFEBABF
        (n,) = u(">I", m, 4)
        if not 0 < n <= 32:
            raise PatchError("fat Mach-O: неправдоподобное число архитектур")
        slices: List[Slice] = []
        for i in range(n):
            if is64:
                cputype, _s, off, sz = u(">IIQQ", m, 8 + 32 * i)
            else:
                cputype, _s, off, sz = u(">IIII", m, 8 + 20 * i)
            if off + sz > size:
                raise PatchError("fat Mach-O: срез выходит за пределы файла")
            arch_name = MACH_CPU_TYPES.get(cputype, f"cputype_0x{cputype:X}")
            raw = macho_thin_ranges(m, off, off + sz)
            slices.append(Slice(name=arch_name, ranges=merge_ranges(raw, size), cputype=cputype))
        return slices, {"is_fat": True}

    raw = macho_thin_ranges(m, 0, size)
    return [Slice(name="main", ranges=merge_ranges(raw, size))], {"is_fat": False}


def exec_slices(m: Union[bytes, mmap.mmap]) -> Tuple[str, List[Slice], Dict[str, Any]]:
    head = bytes(m[:4])
    if head[:2] == b"MZ":
        slices, extra = pe_ranges(m)
        return "PE", slices, extra
    if head == b"\x7fELF":
        slices, extra = elf_ranges(m)
        return "ELF", slices, extra
    (magic,) = u(">I", m, 0)
    if magic in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xCAFEBABF):
        slices, extra = macho_ranges(m)
        return "Mach-O", slices, extra
    raise PatchError("неподдерживаемый формат (нужен PE, ELF или Mach-O)")


def find(m: Union[bytes, mmap.mmap], ranges: List[Tuple[int, int]], regex: re.Pattern, limit: int) -> List[int]:
    res: List[int] = []
    for s, e in ranges:
        pos = s
        while len(res) < limit:
            mt = regex.search(m, pos, e)
            if not mt:
                break
            res.append(mt.start())
            pos = mt.start() + 1
        if len(res) >= limit:
            break
    return res


# --------------------------------------------------------------------------- #
# Анализ файла
# --------------------------------------------------------------------------- #
@dataclass
class TargetWindow:
    slice_name: str
    offset: int
    before: bytes
    target: bytes
    state: str  # "original" | "patched"


@dataclass
class Plan:
    path: str
    fmt: str
    state: str  # "original" | "patched" | "partial"
    size: int
    targets: List[TargetWindow]
    extra: Dict[str, Any] = field(default_factory=dict)


def analyze(job: Job) -> Plan:
    try:
        f = open(job.path, "rb")
    except PermissionError:
        raise PatchError(f"{job.path}: доступ запрещён (возможно, файл запущен другим процессом)")
    except OSError as e:
        raise PatchError(f"не удаётся открыть {job.path}: {e}")

    with f:
        size = os.fstat(f.fileno()).st_size
        if size < 64:
            raise PatchError(f"{job.path}: файл слишком мал для PE/ELF/Mach-O")
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            fmt, all_slices, extra = exec_slices(m)

            # Если указан фильтр архитектуры
            slices = all_slices
            if job.arch:
                slices = [s for s in all_slices if s.name.lower() == job.arch.lower()]
                if not slices:
                    avail = ", ".join(s.name for s in all_slices)
                    raise PatchError(f"{job.path}: архитектура {job.arch!r} не найдена (доступны: {avail})")

            total_ranges = sum(len(s.ranges) for s in slices)
            if total_ranges == 0:
                raise PatchError(f"{job.path}: не найдено исполняемых секций ({fmt})")

            targets: List[TargetWindow] = []
            states = set()

            for sl in slices:
                if not sl.ranges:
                    continue
                mo = find(m, sl.ranges, job.original.regex, 2)
                mp = find(m, sl.ranges, job.patched.regex, 2)
                tot = len(mo) + len(mp)
                if tot == 0:
                    continue
                if tot > 1:
                    raise PatchError(
                        f"{job.path} [{sl.name}]: неоднозначно — найдено ≥2 совпадений "
                        f"(исходных: {len(mo)}, изменённых: {len(mp)}); файл не тронут"
                    )

                w_state, off = ("original", mo[0]) if mo else ("patched", mp[0])
                window = bytes(m[off:off + job.original.length])
                target = job.target_window(window) if w_state == "original" else window
                targets.append(TargetWindow(sl.name, off, window, target, w_state))
                states.add(w_state)

            if not targets:
                raise PatchError(f"{job.path}: сигнатура не найдена в исполняемых секциях ({fmt})")

            if len(states) == 1:
                overall_state = states.pop()
            else:
                overall_state = "partial"

            return Plan(job.path, fmt, overall_state, size, targets, extra)


# --------------------------------------------------------------------------- #
# Низкоуровневые операции с файлами и правами
# --------------------------------------------------------------------------- #
def sha256_file(path: str, patches: Optional[List[Tuple[int, bytes]]] = None) -> str:
    """SHA-256 файла; с patches=[(offset, data), ...] — с подстановкой виртуальных окон."""
    h = hashlib.sha256()
    pos = 0
    plist = sorted(patches) if patches else []
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            if plist:
                chunk_start = pos
                chunk_end = pos + len(chunk)
                for off, data in plist:
                    data_end = off + len(data)
                    s, e = max(off, chunk_start), min(data_end, chunk_end)
                    if s < e:
                        c_s = s - chunk_start
                        c_e = e - chunk_start
                        d_s = s - off
                        d_e = e - off
                        chunk = chunk[:c_s] + data[d_s:d_e] + chunk[c_e:]
            h.update(chunk)
            pos += len(chunk)
    return h.hexdigest()


def ensure_writable(path: str, tx: Optional[Tx] = None) -> None:
    """Проверяет возможность записи и при необходимости временно снимает Read-Only / chmod."""
    try:
        st = os.stat(path)
        if not (st.st_mode & 0o200):  # Нет права на запись владельцу
            os.chmod(path, st.st_mode | 0o200)
            if tx:
                tx.push(f"вернуть права {path}", lambda p=path, m=st.st_mode: os.chmod(p, m))
    except OSError:
        pass


def write_window(path: str, offset: int, data: bytes) -> None:
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def read_window(path: str, offset: int, n: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(n)


def full_restore(path: str, bak: str, expected_sha: Optional[str]) -> None:
    ensure_writable(path)
    tmp = path + ".agytmp"
    try:
        shutil.copy2(bak, tmp)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if expected_sha and sha256_file(path) != expected_sha:
        raise PatchError(f"КРИТИЧНО: после полного восстановления {path} хеш не совпал — проверьте {bak} вручную")


def rollback_windows(path: str, bak: str, targets: List[TargetWindow], sha: str) -> None:
    try:
        for t in targets:
            write_window(path, t.offset, t.before)
            if read_window(path, t.offset, len(t.before)) != t.before:
                raise PatchError("окно не восстановилось")
        if sha256_file(path) != sha:
            raise PatchError("хеш после отката окон не совпал")
    except Exception:
        full_restore(path, bak, sha)


# --------------------------------------------------------------------------- #
# PE CheckSum пересчёт
# --------------------------------------------------------------------------- #
def recalc_pe_checksum(path: str, lfanew: int, tx: Optional[Tx] = None) -> Optional[Tuple[int, bytes, bytes]]:
    """Пересчитывает PE CheckSum, если в заголовке она не нулевая.

    Возвращает (cs_offset, old_bytes, new_bytes) если сумма была обновлена, иначе None.
    """
    cs_offset = lfanew + 0x58
    try:
        with open(path, "r+b") as f:
            f.seek(cs_offset)
            raw = f.read(4)
            if len(raw) < 4:
                return None
            (old_cs,) = struct.unpack("<I", raw)
            if old_cs == 0:
                return None  # Контрольная сумма не используется бинарником

            f.seek(0)
            data = f.read()
            length = len(data)
            limit = length - (length % 2)
            words = struct.unpack(f"<{limit // 2}H", data[:limit])
            skip_idx = cs_offset // 2
            acc = sum(words)
            if skip_idx < len(words):
                acc -= words[skip_idx]
            if skip_idx + 1 < len(words):
                acc -= words[skip_idx + 1]
            if length % 2:
                acc += data[-1]

            while acc >> 16:
                acc = (acc & 0xFFFF) + (acc >> 16)

            new_cs = (acc + length) & 0xFFFFFFFF
            if new_cs != old_cs:
                new_raw = struct.pack("<I", new_cs)
                if tx:
                    tx.push(f"восстановить PE CheckSum {path}",
                            lambda p=path, o=cs_offset, d=raw: write_window(p, o, d))
                f.seek(cs_offset)
                f.write(new_raw)
                f.flush()
                os.fsync(f.fileno())
                log(f"  {c_cyan('PE CheckSum обновлена:')} 0x{old_cs:08X} → 0x{new_cs:08X}")
                return (cs_offset, raw, new_raw)
    except OSError as e:
        log(f"  {c_warn('Не удалось обновить PE CheckSum:')} {e}")
    return None


# --------------------------------------------------------------------------- #
# Резервные копии и верификация
# --------------------------------------------------------------------------- #
def check_backup_for_patched(job: Job, plan: Plan, bak: str) -> None:
    bplan = analyze(Job(bak, job.original, job.patched, arch=job.arch))
    if bplan.state != "original":
        raise PatchError(f"{bak}: в резервной копии нет исходной сигнатуры")
    if plan.fmt == "Mach-O":
        return  # после переподписи Mach-O может отличаться и вне окон

    if len(bplan.targets) != len(plan.targets) or os.path.getsize(bak) != plan.size:
        raise PatchError(f"{bak}: резервная копия не соответствует текущему файлу")

    # Исходные байты окон берем из самого бэкапа (bplan)
    patch_pairs = [(bt.offset, bt.before) for bt in bplan.targets]
    if plan.fmt == "PE" and "lfanew" in plan.extra:
        cs_off = plan.extra["lfanew"] + 0x58
        bak_cs = read_window(bak, cs_off, 4)
        patch_pairs.append((cs_off, bak_cs))

    if sha256_file(job.path, patches=patch_pairs) != sha256_file(bak):
        raise PatchError(f"{bak}: резервная копия не соответствует текущему файлу")


def ensure_backup(job: Job, plan: Plan, before_sha: str) -> bool:
    bak = job.path + BAK_SUFFIX
    if os.path.exists(bak):
        if sha256_file(bak) != before_sha:
            raise PatchError(
                f"{bak} уже существует и НЕ совпадает с текущим оригиналом (устаревший бэкап, "
                f"возможно приложение обновилось). Удалите/переименуйте его вручную."
            )
        return False
    tmp = bak + ".tmp"
    try:
        shutil.copy2(job.path, tmp)
        if os.path.getsize(tmp) != plan.size or sha256_file(tmp) != before_sha:
            raise PatchError(f"резервная копия {bak} не совпала с оригиналом")
        b = analyze(Job(tmp, job.original, job.patched, arch=job.arch))
        if b.state != "original" or len(b.targets) != len(plan.targets):
            raise PatchError(f"резервная копия {bak} не прошла проверку сигнатуры")
        os.replace(tmp, bak)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return True


def verify_applied(job: Job, plan: Plan, bak: str, extra_patches: Optional[List[Tuple[int, bytes]]] = None) -> None:
    for t in plan.targets:
        if read_window(job.path, t.offset, len(t.target)) != t.target:
            raise PatchError(f"проверка записи [{t.slice_name}]: окно 0x{t.offset:X} не совпало с ожидаемым")
    if os.path.getsize(job.path) != plan.size:
        raise PatchError("проверка записи: размер файла изменился")

    patch_pairs = [(t.offset, t.target) for t in plan.targets]
    if extra_patches:
        patch_pairs.extend(extra_patches)

    if sha256_file(job.path) != sha256_file(bak, patches=patch_pairs):
        raise PatchError("проверка записи: SHA-256 файла не совпал с ожидаемым")

    p2 = analyze(job)
    if p2.state != "patched" or len(p2.targets) != len(plan.targets):
        raise PatchError("проверка записи: повторный поиск не подтвердил состояние 'patched'")


# --------------------------------------------------------------------------- #
# Транзакции и обработка сигналов
# --------------------------------------------------------------------------- #
class Tx:
    def __init__(self):
        self.undo: List[Tuple[str, Callable[[], None]]] = []

    def push(self, desc: str, fn: Callable[[], None]) -> None:
        self.undo.append((desc, fn))

    def rollback(self) -> bool:
        ok = True
        for desc, fn in reversed(self.undo):
            try:
                fn()
                log(f"  {c_warn('↩ откат:')} {desc}")
            except Exception as e:
                ok = False
                log(f"  {c_err('✗ ОТКАТ НЕ УДАЛСЯ')} ({desc}): {e}")
        self.undo.clear()
        return ok


_CURRENT_TX: Optional[Tx] = None


def _signal_handler(signum, _frame):
    global _CURRENT_TX
    log(f"\n{c_err('!')} Получен сигнал {signum}. Экстренное прерывание...")
    if _CURRENT_TX:
        _CURRENT_TX.rollback()
    sys.exit(128 + signum)


# --------------------------------------------------------------------------- #
# macOS: сохранение и восстановление подписи .app
# --------------------------------------------------------------------------- #
def outer_app(path: str) -> Optional[Path]:
    outer = None
    for a in Path(os.path.realpath(path)).parents:
        if a.suffix == ".app":
            outer = a
    return outer


def bundle_chain(path: str, root: Path) -> List[Path]:
    out = []
    for a in Path(os.path.realpath(path)).parents:
        if a.suffix in BUNDLE_EXT:
            out.append(a)
        if a == root:
            break
    return out


def main_executable(bundle: Path) -> Optional[Path]:
    for plist, exedirs in (("Contents/Info.plist", ["Contents/MacOS"]),
                           ("Resources/Info.plist", [""]),
                           ("Versions/Current/Resources/Info.plist", ["Versions/Current"])):
        pl = bundle / plist
        if pl.is_file():
            try:
                name = plistlib.loads(pl.read_bytes()).get("CFBundleExecutable")
            except Exception:
                continue
            if name:
                for ed in exedirs:
                    c = bundle / ed / name
                    if c.is_file():
                        return Path(os.path.realpath(c))
    return None


def sig_dirs(bundle: Path) -> List[Path]:
    cands = [bundle / "Contents" / "_CodeSignature", bundle / "_CodeSignature"]
    cands += sorted(bundle.glob("Versions/*/_CodeSignature"))
    return [Path(os.path.realpath(d)) for d in cands if d.is_dir() and not d.is_symlink()]


def tree_hash(p: Path) -> str:
    h = hashlib.sha256()
    for dp, dn, fn in os.walk(p):
        dn.sort()
        for name in sorted(fn):
            fp = Path(dp) / name
            h.update(os.path.relpath(fp, p).encode() + b"\0")
            if fp.is_symlink():
                h.update(b"L" + os.readlink(fp).encode())
            else:
                h.update(bytes.fromhex(sha256_file(str(fp))))
    return h.hexdigest()


def item_hash(p: Path, kind: str) -> str:
    return tree_hash(p) if kind == "dir" else sha256_file(str(p))


def sign_dir_of(root: Path) -> Path:
    return root.with_name(root.name + SIGN_SUFFIX)


def snapshot_items(root: Path, chain: List[Path], targets: set) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    rr = Path(os.path.realpath(root))
    for b in chain:
        for d in sig_dirs(b):
            items.append((os.path.relpath(d, rr), "dir"))
        exe = main_executable(b)
        if exe and str(exe) not in targets:
            items.append((os.path.relpath(exe, rr), "file"))
    return list(dict.fromkeys(items))


def snapshot_matches_current(root: Path, sdir: Path) -> bool:
    man = json.loads((sdir / "manifest.json").read_text(encoding="utf-8"))
    rr = Path(os.path.realpath(root))
    try:
        return all(item_hash(rr / it["rel"], it["kind"]) == it["sha256"] for it in man["items"])
    except OSError:
        return False


def take_snapshot(root: Path, items: List[Tuple[str, str]]) -> Path:
    rr = Path(os.path.realpath(root))
    sdir = sign_dir_of(root)
    tmp = sdir.with_name(sdir.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "files").mkdir(parents=True)
    man = []
    try:
        for rel, kind in items:
            src, dst = rr / rel, tmp / "files" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if kind == "dir":
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst)
            h = item_hash(src, kind)
            if item_hash(dst, kind) != h:
                raise PatchError(f"снимок подписи: {rel} скопирован с ошибкой")
            man.append({"rel": rel, "kind": kind, "sha256": h})
        info = subprocess.run(["codesign", "-dvv", "--entitlements", "-", str(root)],
                              capture_output=True, text=True) if shutil.which("codesign") else None
        (tmp / "codesign-info.txt").write_text(
            (info.stdout + info.stderr) if info else "codesign недоступен", encoding="utf-8")
        (tmp / "manifest.json").write_text(
            json.dumps({"version": 1, "app": root.name, "items": man}, indent=2), encoding="utf-8")
        os.rename(tmp, sdir)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return sdir


def restore_snapshot(root: Path, sdir: Path) -> None:
    man = json.loads((sdir / "manifest.json").read_text(encoding="utf-8"))
    rr = Path(os.path.realpath(root))
    for it in man["items"]:
        src, dst = sdir / "files" / it["rel"], rr / it["rel"]
        if it["kind"] == "dir":
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=True)
        else:
            tmp = dst.with_name(dst.name + ".agytmp")
            shutil.copy2(src, tmp)
            os.replace(tmp, dst)
        if item_hash(dst, it["kind"]) != it["sha256"]:
            raise PatchError(f"восстановление подписи: {it['rel']} не совпал с манифестом")


def run_cmd(cmd: List[str]) -> None:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode:
        raise PatchError(f"{' '.join(cmd)} → код {p.returncode}: {(p.stderr or p.stdout).strip()}")


def resign(root: Path, targets: List[str], chain: List[Path]) -> None:
    inner_exes = {str(main_executable(b)) for b in chain if main_executable(b)}
    for t in targets:
        if os.path.realpath(t) not in inner_exes:
            run_cmd(["codesign", "--force", "--sign", "-", t])
    ordered = sorted(chain, key=lambda p: len(p.parts), reverse=True)
    for b in ordered:
        run_cmd(["codesign", "--force", "--sign", "-",
                 "--preserve-metadata=identifier,entitlements,flags,runtime", str(b)])
    for b in ordered:
        run_cmd(["codesign", "--verify", "--strict", str(b)])


# --------------------------------------------------------------------------- #
# Команды: status, patch, restore
# --------------------------------------------------------------------------- #
def cmd_status(jobs: List[Job], verbose: bool = False) -> int:
    rc = 0
    for j in jobs:
        header = f"• {j.path}" + (f" ({c_bold(j.name)})" if j.name else "")
        log(header)
        try:
            p = analyze(j)
        except PatchError as e:
            log(f"  {c_err('✗')} {e}")
            rc = 1
            continue

        bak = j.path + BAK_SUFFIX
        b_status = "нет"
        if os.path.exists(bak):
            try:
                if p.state == "original":
                    b_status = c_ok("есть, OK") if sha256_file(bak) == sha256_file(j.path) else c_warn("есть, УСТАРЕЛ")
                else:
                    check_backup_for_patched(j, p, bak)
                    b_status = c_ok("есть, OK")
            except PatchError as e:
                b_status = c_err(f"есть, ПРОБЛЕМА: {e}")

        state_str = (
            c_ok("оригинал (можно патчить)") if p.state == "original"
            else c_warn("уже изменён") if p.state == "patched"
            else c_err("частично изменён")
        )

        log(f"    Формат:    {p.fmt}")
        log(f"    Состояние: {state_str}")
        log(f"    Бэкап:     {b_status}")

        if p.extra.get("has_authenticode"):
            log(f"    {c_warn('Подпись:')}   PE содержит Authenticode (изменение кода инвалидирует её)")

        for t in p.targets:
            slice_info = f" [{t.slice_name}]" if t.slice_name != "main" else ""
            log(f"    Окно{slice_info}:  0x{t.offset:08X} ({t.state})")
            if verbose or p.state == "original":
                log(format_hex_diff(t.offset, t.before, t.target))

        if IS_DARWIN and p.fmt == "Mach-O" and (r := outer_app(j.path)):
            has_sign = sign_dir_of(r).exists()
            log(f"    Подпись .app: {c_ok('снимок есть') if has_sign else 'снимка нет'}")
    return rc


def apply_job(job: Job, plan: Plan, tx: Tx, dry_run: bool = False) -> None:
    bak = job.path + BAK_SUFFIX
    before_sha = sha256_file(job.path)

    if not dry_run:
        ensure_writable(job.path, tx)
        if ensure_backup(job, plan, before_sha):
            tx.push(f"удалить {bak}", lambda: os.remove(bak))
        log(f"  {c_ok('бэкап проверен:')} {bak}")
        tx.push(f"вернуть {job.path}",
                lambda: rollback_windows(job.path, bak, plan.targets, before_sha))

    for t in plan.targets:
        slice_label = f" [{t.slice_name}]" if t.slice_name != "main" else ""
        if dry_run:
            log(f"  {c_cyan('[DRY-RUN]')} Будет изменено{slice_label}:")
            log(format_hex_diff(t.offset, t.before, t.target))
        else:
            write_window(job.path, t.offset, t.target)
            log(f"  {c_ok('записано:')}{slice_label} 0x{t.offset:08X} ({len(t.target)} байт)")

    if not dry_run:
        extra_patches = []
        # Пересчёт PE CheckSum при необходимости
        if plan.fmt == "PE" and "lfanew" in plan.extra:
            cs_res = recalc_pe_checksum(job.path, plan.extra["lfanew"], tx)
            if cs_res:
                cs_off, _old_b, new_b = cs_res
                extra_patches.append((cs_off, new_b))

        verify_applied(job, plan, bak, extra_patches=extra_patches)
        log(f"  {c_ok('проверка пройдена:')} хеш и сигнатура подтверждены")


def cmd_patch(jobs: List[Job], do_resign: bool = True, dry_run: bool = False) -> int:
    global _CURRENT_TX
    paths = [os.path.realpath(j.path) for j in jobs]
    if len(set(paths)) != len(paths):
        log(f"{c_err('✗')} один и тот же файл указан несколько раз")
        return 1

    try:
        plans = [(j, analyze(j)) for j in jobs]
    except PatchError as e:
        log(f"{c_err('✗')} {e}")
        return 1

    tx = Tx()
    _CURRENT_TX = tx

    # Регистрация обработчиков сигналов для корректного отката
    old_sigterm = signal.signal(signal.SIGTERM, _signal_handler)
    old_sighup = signal.signal(signal.SIGHUP, _signal_handler) if hasattr(signal, "SIGHUP") else None

    try:
        groups: Dict[Path, List[Tuple[Job, Plan]]] = {}
        if IS_DARWIN and not dry_run:
            for j, p in plans:
                if p.fmt == "Mach-O" and (r := outer_app(j.path)):
                    groups.setdefault(r, []).append((j, p))

        # Снимок подписи macOS до начала любых изменений
        for root, members in groups.items():
            sdir = sign_dir_of(root)
            if not any(p.state in ("original", "partial") for _, p in members):
                continue
            targets = {os.path.realpath(j.path) for j, _ in members}
            chain: List[Path] = []
            for j, _ in members:
                chain += [c for c in bundle_chain(j.path, root) if c not in chain]
            if sdir.exists():
                if not snapshot_matches_current(root, sdir):
                    raise PatchError(f"{sdir} не совпадает с текущей подписью (устарел). Удалите его вручную.")
            else:
                take_snapshot(root, snapshot_items(root, chain, targets))
                tx.push(f"удалить {sdir}", lambda s=sdir: shutil.rmtree(s))
            log(f"Снимок подписи сохранён: {sdir}")

        changed: List[Tuple[Job, Plan]] = []
        for j, p in plans:
            title = f"→ {j.path} [{p.fmt}]" + (f" ({c_bold(j.name)})" if j.name else "")
            log(title)
            if p.extra.get("has_authenticode"):
                log(f"  {c_warn('Внимание:')} PE имеет Authenticode-подпись. Патч нарушит её целостность.")

            if p.state == "patched":
                bak = j.path + BAK_SUFFIX
                if os.path.exists(bak):
                    check_backup_for_patched(j, p, bak)
                    log(f"  {c_ok('уже изменён')}, резервная копия в порядке — пропуск")
                else:
                    log(f"  {c_warn('уже изменён')}, но .agybak не найден — пропуск (откат невозможен)")
                continue

            apply_job(j, p, tx, dry_run=dry_run)
            changed.append((j, p))

        if IS_DARWIN and do_resign and not dry_run:
            for root, members in groups.items():
                mine = [j.path for j, p in members if (j, p) in changed]
                if not mine:
                    continue
                chain = []
                for j in mine:
                    chain += [c for c in bundle_chain(j, root) if c not in chain]
                sdir = sign_dir_of(root)
                tx.push(f"вернуть подпись {root.name}", lambda r=root, s=sdir: restore_snapshot(r, s))
                log(f"Переподпись (ad-hoc): {root.name}")
                resign(root, mine, chain)

    except (Exception, KeyboardInterrupt) as e:
        log(f"\n{c_err('✗ ОШИБКА:')} {e}\n  выполняю откат...")
        ok = tx.rollback()
        log(c_ok("откат завершён, файлы возвращены в исходное состояние") if ok else
            c_err("ВНИМАНИЕ: откат завершён с ошибками, проверьте резервные копии вручную"))
        if isinstance(e, KeyboardInterrupt):
            raise
        return 1
    finally:
        _CURRENT_TX = None
        signal.signal(signal.SIGTERM, old_sigterm)
        if old_sighup:
            signal.signal(signal.SIGHUP, old_sighup)

    if dry_run:
        log(f"\n{c_ok('✓ [DRY-RUN]')} Все проверки пройдены успешно. Изменения на диск не вносились.")
    else:
        log(f"\n{c_ok('✓ Готово!')}")
    return 0


def cmd_restore(jobs: List[Job], keep: bool = False, force: bool = False) -> int:
    rc = 0
    roots: set = set()
    done: List[str] = []
    for j in jobs:
        bak = j.path + BAK_SUFFIX
        try:
            if not os.path.exists(bak):
                raise PatchError(f"{bak} не найден")
            b = analyze(Job(bak, j.original, j.patched, arch=j.arch))
            if b.state != "original":
                raise PatchError(f"{bak}: в бэкапе нет исходной сигнатуры")
            cur = analyze(j)
            bsha = sha256_file(bak)
            cur_sha = sha256_file(j.path)

            if cur.state == "original" and cur_sha == bsha:
                log(f"• {j.path}: уже оригинал")
            else:
                if cur.state == "original" and not force:
                    raise PatchError(f"{j.path}: файл отличается от бэкапа (обновлён?). Используйте --force")
                if cur.state == "patched" and cur.fmt != "Mach-O" and not force:
                    patch_pairs = [(t.offset, t.before) for t in b.targets]
                    if sha256_file(j.path, patches=patch_pairs) != bsha:
                        raise PatchError(f"{j.path}: бэкап не соответствует текущему файлу. Используйте --force")

                full_restore(j.path, bak, bsha)
                after = analyze(j)
                if after.state != "original":
                    raise PatchError(f"{j.path}: после восстановления сигнатура не исходная")
                log(f"{c_ok('✓')} восстановлен {j.path}")

            done.append(bak)
            if IS_DARWIN and (r := outer_app(j.path)) and sign_dir_of(r).exists():
                roots.add(r)
        except PatchError as e:
            log(f"{c_err('✗')} {e}")
            rc = 1

    if rc == 0:
        for r in roots:
            restore_snapshot(r, sign_dir_of(r))
            log(f"{c_ok('✓')} подпись {r.name} восстановлена из снимка")
        if not keep:
            for bak in done:
                try:
                    os.remove(bak)
                except OSError:
                    pass
            for r in roots:
                shutil.rmtree(sign_dir_of(r), ignore_errors=True)
    return rc


# --------------------------------------------------------------------------- #
# CLI парсинг
# --------------------------------------------------------------------------- #
def build_jobs(args) -> List[Job]:
    jobs: List[Job] = []
    if args.config:
        base = os.path.dirname(os.path.abspath(args.config))
        try:
            with open(args.config, encoding="utf-8") as f:
                data = json.load(f)
            for p in data["patches"]:
                raw_path = os.path.expandvars(os.path.expanduser(p["file"]))
                fpath = raw_path if os.path.isabs(raw_path) else os.path.join(base, raw_path)
                jobs.append(Job(
                    path=os.path.abspath(fpath),
                    original=Pattern(p["original"]),
                    patched=Pattern(p["patched"]),
                    name=p.get("name"),
                    arch=p.get("arch", args.arch if hasattr(args, "arch") else None),
                ))
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise PatchError(f"ошибка конфига {args.config}: {e!r}")

    if args.file:
        if not (args.original and args.patched):
            raise PatchError("для --file требуются параметры --original и --patched")
        jobs.append(Job(
            path=os.path.abspath(args.file),
            original=Pattern(args.original),
            patched=Pattern(args.patched),
            name=getattr(args, "name", None),
            arch=getattr(args, "arch", None),
        ))

    if not jobs:
        raise PatchError("укажите --config <путь> или комбинацию --file / --original / --patched")
    return jobs


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", help="JSON-конфиг со списком патчей")
    common.add_argument("-f", "--file", help="целевой бинарник (вместо конфига)")
    common.add_argument("-o", "--original", help="исходная сигнатура (hex, ?? = wildcard)")
    common.add_argument("-p", "--patched", help="заменяющая сигнатура (hex, ?? = оставить как есть)")
    common.add_argument("-a", "--arch", help="выбрать конкретную архитектуру в Fat Mach-O (напр. x86_64, arm64)")
    common.add_argument("-v", "--verbose", action="store_true", help="подробный вывод")

    ap = argparse.ArgumentParser(
        description="agy_patcher — безопасный кроссплатформенный сигнатурный патчер для PE / ELF / Mach-O"
    )
    ap.add_argument("--version", action="version", version=f"agy_patcher {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # status
    sub.add_parser("status", parents=[common], help="проверить состояние файлов и сигнатур без записи")

    # patch
    sp = sub.add_parser("patch", parents=[common], help="применить патч (с транзакционным бэкапом)")
    sp.add_argument("-n", "--dry-run", action="store_true", help="только проверка и симуляция без изменения файлов")
    sp.add_argument("--no-resign", action="store_true", help="macOS: пропустить ad-hoc переподпись")

    # restore
    sr = sub.add_parser("restore", parents=[common], help="восстановить оригиналы из *.agybak")
    sr.add_argument("--keep", action="store_true", help="сохранить файлы бэкапа после успешного восстановления")
    sr.add_argument("--force", action="store_true", help="принудительно восстановить при несовпадении хешей")

    args = ap.parse_args(argv)
    try:
        jobs = build_jobs(args)
    except PatchError as e:
        log(f"{c_err('✗')} {e}")
        return 2

    if args.cmd == "status":
        return cmd_status(jobs, verbose=args.verbose)
    if args.cmd == "patch":
        return cmd_patch(jobs, do_resign=not args.no_resign, dry_run=args.dry_run)
    return cmd_restore(jobs, keep=args.keep, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
