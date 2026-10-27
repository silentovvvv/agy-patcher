#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

# Добавляем родительский каталог в sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agy_patcher as patcher


class TestPattern(unittest.TestCase):
    def test_valid_patterns(self):
        p = patcher.Pattern("48 8B ?? 05 00 00 00")
        self.assertEqual(p.length, 7)
        self.assertTrue(p.matches(bytes.fromhex("48 8B 12 05 00 00 00")))
        self.assertFalse(p.matches(bytes.fromhex("48 8B 12 06 00 00 00")))

    def test_min_concrete(self):
        with self.assertRaises(patcher.PatchError):
            patcher.Pattern("48 ?? ?? ??")  # только 1 конкретный байт при минимуме 4

    def test_job_validation(self):
        o = patcher.Pattern("48 8B 05 00 00")
        p = patcher.Pattern("48 8B 05 00 01")
        job = patcher.Job("dummy", o, p)
        self.assertEqual(job.target_window(b"\x48\x8B\x05\x00\x00"), b"\x48\x8B\x05\x00\x01")

        # Разная длина
        with self.assertRaises(patcher.PatchError):
            patcher.Job("dummy", o, patcher.Pattern("90 90 90 90"))

        # Одинаковые байты
        with self.assertRaises(patcher.PatchError):
            patcher.Job("dummy", o, o)


class TestBinaryPatching(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_minimal_pe(self, code_bytes: bytes) -> str:
        """Создает синтетический минимальный PE с исполняемой секцией .text"""
        path = os.path.join(self.tmp_dir, "test.exe")
        dos_hdr = bytearray(0x40)
        dos_hdr[0:2] = b"MZ"
        struct.pack_into("<I", dos_hdr, 0x3C, 0x40)  # e_lfanew = 0x40

        # PE signature
        pe_sig = b"PE\0\0"

        # COFF File Header (20 bytes)
        # Machine=0x8664 (x64), NumberOfSections=1, TimeDateStamp=0, ... SizeOfOptionalHeader=0xF0, Characteristics=0x22
        coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)

        # Optional Header (PE32+ 0x20B, 240 bytes)
        opt = bytearray(0xF0)
        struct.pack_into("<H", opt, 0, 0x20B)  # Magic = PE32+
        struct.pack_into("<I", opt, 0x58, 0x1234)  # CheckSum dummy

        # Section Header (.text, 40 bytes)
        # Name=8s, VirtualSize=I, VirtualAddress=I, SizeOfRawData=I, PointerToRawData=I, ... Characteristics=I
        raw_ptr = 0x200
        raw_size = max(len(code_bytes), 0x200)
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            b".text\0\0\0",
            len(code_bytes),
            0x1000,
            raw_size,
            raw_ptr,
            0,
            0,
            0,
            0,
            0x60000020,  # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        )

        pe_content = bytearray(raw_ptr + raw_size)
        pe_content[0:0x40] = dos_hdr
        pe_content[0x40:0x44] = pe_sig
        pe_content[0x44:0x58] = coff
        pe_content[0x58:0x148] = opt
        pe_content[0x148:0x170] = sec_hdr
        pe_content[raw_ptr:raw_ptr + len(code_bytes)] = code_bytes

        with open(path, "wb") as f:
            f.write(pe_content)
        return path

    def test_pe_patch_and_restore(self):
        # 48 8B 05 11 22 33 44 -> 48 8B 05 90 90 90 90
        code = b"\x90\x90" + bytes.fromhex("48 8B 05 11 22 33 44") + b"\xC3"
        pe_path = self._create_minimal_pe(code)

        orig_pat = patcher.Pattern("48 8B 05 11 22 33 44")
        patch_pat = patcher.Pattern("48 8B 05 90 90 90 90")
        job = patcher.Job(pe_path, orig_pat, patch_pat, name="Test PE Patch")

        # 1. Проверяем статус до патча
        plan = patcher.analyze(job)
        self.assertEqual(plan.state, "original")
        self.assertEqual(len(plan.targets), 1)

        # 2. Dry-run не изменяет файл
        res = patcher.cmd_patch([job], dry_run=True)
        self.assertEqual(res, 0)
        self.assertFalse(os.path.exists(pe_path + patcher.BAK_SUFFIX))
        plan_after_dry = patcher.analyze(job)
        self.assertEqual(plan_after_dry.state, "original")

        # 3. Реальный патч
        res = patcher.cmd_patch([job], dry_run=False)
        self.assertEqual(res, 0)
        self.assertTrue(os.path.exists(pe_path + patcher.BAK_SUFFIX))

        # Состояние должно стать patched
        plan_patched = patcher.analyze(job)
        self.assertEqual(plan_patched.state, "patched")

        # Повторный запуск иденпотентен
        res_repeat = patcher.cmd_patch([job])
        self.assertEqual(res_repeat, 0)

        # 4. Восстановление
        res_restore = patcher.cmd_restore([job])
        self.assertEqual(res_restore, 0)
        self.assertFalse(os.path.exists(pe_path + patcher.BAK_SUFFIX))
        plan_restored = patcher.analyze(job)
        self.assertEqual(plan_restored.state, "original")

    def test_pe_checksum_recalc(self):
        code = b"\x90" * 32 + bytes.fromhex("48 89 E5 55 90 90")
        pe_path = self._create_minimal_pe(code)

        job = patcher.Job(
            pe_path,
            patcher.Pattern("48 89 E5 55 90 90"),
            patcher.Pattern("48 89 E5 55 CC CC"),
        )
        plan = patcher.analyze(job)
        self.assertIn("lfanew", plan.extra)
        lfanew = plan.extra["lfanew"]

        # Записываем известную ненулевую контрольную сумму
        cs_off = lfanew + 0x58
        with open(pe_path, "r+b") as f:
            f.seek(cs_off)
            f.write(struct.pack("<I", 0x123456))

        # Патчим
        patcher.cmd_patch([job])

        # Читаем новую чексумму
        with open(pe_path, "rb") as f:
            f.seek(cs_off)
            (new_cs,) = struct.unpack("<I", f.read(4))

        self.assertNotEqual(new_cs, 0x123456)
        self.assertNotEqual(new_cs, 0)

    def _create_minimal_elf64(self, code_bytes: bytes) -> str:
        """Создает синтетический минимальный ELF64 с PT_LOAD PF_X"""
        path = os.path.join(self.tmp_dir, "test.elf")
        code_off = 0x100
        # ELF Header (64 bytes)
        # e_ident: 16 bytes
        ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        # e_type=2, e_machine=0x3E, e_version=1, e_entry=0x400100, e_phoff=0x40, e_shoff=0, e_flags=0, e_ehsize=64, e_phentsize=56, e_phnum=1, e_shentsize=64, e_shnum=0, e_shstrndx=0
        hdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident,
            2,
            0x3E,
            1,
            0x400100,
            0x40,
            0,
            0,
            64,
            56,
            1,
            64,
            0,
            0,
        )
        # Program Header (56 bytes for ELF64):
        # p_type=1 (PT_LOAD), p_flags=5 (PF_R | PF_X), p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
        phdr = struct.pack(
            "<IIQQQQQQ",
            1,
            5,
            code_off,
            0x400100,
            0x400100,
            len(code_bytes),
            len(code_bytes),
            0x1000,
        )
        content = bytearray(code_off + len(code_bytes))
        content[0:64] = hdr
        content[64:120] = phdr
        content[code_off:code_off + len(code_bytes)] = code_bytes
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_elf_patch(self):
        code = b"\x90" * 16 + bytes.fromhex("48 89 E5 5D C3 90 90")
        elf_path = self._create_minimal_elf64(code)
        job = patcher.Job(
            elf_path,
            patcher.Pattern("48 89 E5 5D C3 90 90"),
            patcher.Pattern("48 89 E5 5D C3 CC CC"),
            name="Test ELF Patch",
        )
        plan = patcher.analyze(job)
        self.assertEqual(plan.fmt, "ELF")
        self.assertEqual(plan.state, "original")
        res = patcher.cmd_patch([job])
        self.assertEqual(res, 0)
        self.assertEqual(patcher.analyze(job).state, "patched")

    def _create_minimal_macho_thin(self, code_bytes: bytes) -> str:
        """Создает синтетический thin Mach-O 64-bit"""
        path = os.path.join(self.tmp_dir, "test.macho")
        code_off = 0x200
        # mach_header_64 (32 bytes):
        # magic=0xFEEDFACF, cputype=0x01000007 (x86_64), cpusubtype=3, filetype=2, ncmds=1, sizeofcmds=72+80=152, flags=0x85, reserved=0
        mhdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, 152, 0x85, 0)

        # LC_SEGMENT_64 (72 bytes + 80 bytes for 1 section = 152 bytes)
        # cmd=0x19, cmdsize=152, segname=16s, vmaddr=Q, vmsize=Q, fileoff=Q, filesize=Q, maxprot=I, initprot=I (7: rwx), nsects=I, flags=I
        seg_cmd = struct.pack(
            "<II16sQQQQIIII",
            0x19,
            152,
            b"__TEXT\0" * 2,
            0x1000,
            0x1000,
            0,
            code_off + len(code_bytes),
            7,
            7,
            1,
            0,
        )
        # section_64 (80 bytes)
        # sectname=16s, segname=16s, addr=Q, size=Q, offset=I, align=I, reloff=I, nreloc=I, flags=I, reserved1=I, reserved2=I, reserved3=I
        sec_cmd = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text\0" * 2,
            b"__TEXT\0" * 2,
            0x1000 + code_off,
            len(code_bytes),
            code_off,
            4,
            0,
            0,
            0x80000400,  # S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
            0,
            0,
            0,
        )
        content = bytearray(code_off + len(code_bytes))
        content[0:32] = mhdr
        content[32:104] = seg_cmd
        content[104:184] = sec_cmd
        content[code_off:code_off + len(code_bytes)] = code_bytes
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_macho_thin_patch(self):
        code = b"\x90" * 16 + bytes.fromhex("55 48 89 E5 5D C3 90")
        macho_path = self._create_minimal_macho_thin(code)
        job = patcher.Job(
            macho_path,
            patcher.Pattern("55 48 89 E5 5D C3 90"),
            patcher.Pattern("55 48 89 E5 5D C3 CC"),
            name="Test Mach-O Thin",
        )
        plan = patcher.analyze(job)
        self.assertEqual(plan.fmt, "Mach-O")
        self.assertEqual(plan.state, "original")
        res = patcher.cmd_patch([job], do_resign=False)
        self.assertEqual(res, 0)
        self.assertEqual(patcher.analyze(job).state, "patched")


    def test_outdated_backup_auto_rotation(self):
        # Проверяем поведение при обновлении приложения, когда остался старый .agybak
        code = b"\x90\x90" + bytes.fromhex("48 8B 05 11 22 33 44") + b"\xC3"
        pe_path = self._create_minimal_pe(code)

        orig_pat = patcher.Pattern("48 8B 05 11 22 33 44")
        patch_pat = patcher.Pattern("48 8B 05 90 90 90 90")
        job = patcher.Job(pe_path, orig_pat, patch_pat, name="Test Outdated Backup")

        # Создаем искусственный устаревший .agybak (от старой версии приложения)
        bak_path = pe_path + patcher.BAK_SUFFIX
        old_bak_path = bak_path + ".old"
        with open(bak_path, "wb") as f:
            f.write(b"OLD_VERSION_BACKUP_CONTENT" * 32)

        # Применяем патч — должно автоматически обнаружить обновление,
        # перенести старый бэкап в .agybak.old, создать новый .agybak и успешно пропатчить
        res = patcher.cmd_patch([job])
        self.assertEqual(res, 0)

        # Проверяем, что старый бэкап сохранен в .agybak.old
        self.assertTrue(os.path.exists(old_bak_path))
        with open(old_bak_path, "rb") as f:
            self.assertEqual(f.read(), b"OLD_VERSION_BACKUP_CONTENT" * 32)

        # Проверяем, что новый .agybak создан и соответствует исходному оригиналу
        self.assertTrue(os.path.exists(bak_path))
        self.assertEqual(patcher.analyze(patcher.Job(bak_path, orig_pat, patch_pat)).state, "original")

        # Файл успешно пропатчен
        self.assertEqual(patcher.analyze(job).state, "patched")

    def test_cli_arg_parsing(self):
        # Проверяем корректность регистрации аргументов командной строки (отсутствие конфликтов флагов)
        with self.assertRaises(SystemExit) as cm:
            patcher.main(["patch", "--help"])
        self.assertEqual(cm.exception.code, 0)

        with self.assertRaises(SystemExit) as cm:
            patcher.main(["status", "--help"])
        self.assertEqual(cm.exception.code, 0)

        with self.assertRaises(SystemExit) as cm:
            patcher.main(["restore", "--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
