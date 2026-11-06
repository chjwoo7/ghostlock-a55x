#!/usr/bin/env python3
"""
port_a55.py -- build the CVE-2026-43499 target header set for a Samsung
SM-A556 (a55x / Galaxy A55 5G, Exynos 1480) firmware image.

This automates steps 2-6 of
  https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/main/docs/PORTING.md
against your own boot.img, and emits the same constants the shipped
`src/targets/<device>-<build>/target.h` files contain.

What it can derive without a device:
  * boot-header v4 -> raw ARM64 Image (kernel), with provenance hashes
  * validated raw BTF blob
  * symbolized ELF (via vmlinux-to-elf) + own ELF/SYMTAB reader
  * every *_OFF symbol macro by name, offsets relative to _text
  * tstruct/file_operations/page/ctl_table/miscdevice layout offsets from BTF
  * sched_blocked_reason trace event id (__start_ftrace_events / __event_*)
  * worker_thread post-`bl schedule` caller offset
  * SLIDE_NFULNL_LOGGER_NAME_OFF by dereferencing nfulnl_logger->name
  * SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF by walking random_table[]
  * p0 fingerprint table (slides 0x000000..0x1f0000, step 0x10000)

What it CANNOT derive (needs hardware / manual stack analysis, left as TODO):
  * SLIDE_PSELECT_WORD_SHIFT   (fd_set -> rt_mutex_waiter stack overlap)
  * P0_KERNEL_PHYS_LOAD        (needs BL/sboot.bin from the same firmware)
  * confirmation that the P0 route is even reachable on this bootloader

Requirements: python 3.10+, `pip install lz4` (or lz4 CLI), vmlinux-to-elf on
PATH, and optionally bpftool (BTF) + capstone/llvm-objdump (disassembly).

Usage:
  python port_a55.py --boot boot.img --out out-a55x --pda A556EXXU...
  python port_a55.py --boot boot.img.lz4 --out out-a55x --trace-event-id 106
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------- constants --
PAGE = 0x1000
P0_PAGE_OFFSET = 0xFFFFFF8000000000
P0_PHYS_OFFSET = 0x80000000
VMEMMAP_START = 0xFFFFFFFE00000000
DIRECT_MAP_BASE = 0xFFFFFF8000000000
TRACE_LAST_TYPE_ANDROID_6_1 = 20
SLIDE_STEP = 0x10000
SLIDE_MAX = 0x1F0000
P0_ROW_OFFSETS = (0x000, 0x200, 0x400, 0x600, 0x800, 0xA00, 0xC00, 0xE00)

SYMBOL_MACROS = [
    # (macro, symbol, extra)
    ("CALL_USERMODEHELPER_EXEC_WORK_OFF", "call_usermodehelper_exec_work", 0),
    ("NOOP_LLSEEK_OFF", "noop_llseek", 0),
    ("COPY_SPLICE_READ_OFF", "generic_file_splice_read", 0),
    ("CONFIGFS_READ_ITER_OFF", "configfs_read_iter", 0),
    ("CONFIGFS_BIN_WRITE_ITER_OFF", "configfs_bin_write_iter", 0),
    ("ASHMEM_IOCTL_OFF", "ashmem_ioctl", 0),
    ("ASHMEM_COMPAT_IOCTL_OFF", "compat_ashmem_ioctl", 0),
    ("ASHMEM_MMAP_OFF", "ashmem_mmap", 0),
    ("ASHMEM_OPEN_OFF", "ashmem_open", 0),
    ("ASHMEM_RELEASE_OFF", "ashmem_release", 0),
    ("ASHMEM_SHOW_FDINFO_OFF", "ashmem_show_fdinfo", 0),
    ("ANON_PIPE_BUF_OPS_OFF", "anon_pipe_buf_ops", 0),
    ("ASHMEM_FOPS_OFF", "ashmem_fops", 0),
    ("KMALLOC_CACHES_OFF", "kmalloc_caches", 0),
    ("SYSTEM_UNBOUND_WQ_OFF", "system_unbound_wq", 0),
    ("SLIDE_NFULNL_LOGGER_OBJECT_OFF", "nfulnl_logger", 0),
    ("INIT_TASK_OFF", "init_task", 0),
    ("ROOT_TASK_GROUP_OFF", "root_task_group", 0),
    ("SLIDE_SYSCTL_BOOTID_OFF", "sysctl_bootid", 0),
]

STRUCT_FIELDS = {
    "task_struct": ["usage", "prio", "normal_prio", "sched_task_group", "pi_lock",
                    "pi_waiters", "pi_top_task", "pi_blocked_on"],
    "file_operations": ["unlocked_ioctl", "compat_ioctl", "mmap", "open", "release",
                        "splice_read", "show_fdinfo"],
    "page": ["compound_head", "slab_cache", "page_type"],
    "cred": ["uid", "cap_inheritable", "cap_permitted", "cap_effective", "cap_bset",
             "cap_ambient", "security", "user", "user_ns", "ucounts", "group_info"],
    "miscdevice": ["fops"],
    "selinux_state": ["enforcing"],
    "ctl_table": ["name", "data", "size"],
}

problems: list[str] = []


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.exit(f"[fatal] {msg}")


def note(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------- unpacking --
def decompress_auto(blob: bytes, what: str) -> bytes:
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)
    if blob[:4] == b"\x04\x22\x4d\x18":
        return _lz4(blob, what)
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        return _zstd(blob, what)
    if blob[:2] == b"\x1f\x9d" or blob[:2] == b"\x1f\xa0":
        return _cli(["gzip", "-dc"], blob, what)
    if blob[0x38:0x3c] == b"ARM\x64":
        return blob  # already a raw ARM64 Image
    return blob


def _lz4(blob: bytes, what: str) -> bytes:
    try:
        import lz4.frame  # type: ignore

        return lz4.frame.decompress(blob)
    except Exception:
        return _cli(["lz4", "-dc"], blob, what)


def _zstd(blob: bytes, what: str) -> bytes:
    try:
        import zstandard  # type: ignore

        return zstandard.ZstdDecompressor().decompress(blob, max_output_size=1 << 31)
    except Exception:
        return _cli(["zstd", "-dc"], blob, what)


def _cli(argv: list[str], blob: bytes, what: str) -> bytes:
    exe = shutil.which(argv[0])
    if not exe:
        die(f"cannot decompress {what}: install '{argv[0]}' or the python module")
    p = subprocess.run([exe, *argv[1:]], input=blob, capture_output=True)
    if p.returncode != 0:
        die(f"cannot decompress {what}: {p.stderr.decode(errors='replace')[:400]}")
    return p.stdout


def unpack_boot(path: Path, out: Path) -> tuple[Path, bytes]:
    raw = path.read_bytes()
    if path.suffix == ".lz4":
        raw = _lz4(raw, "boot.img.lz4")
    if raw[:8] != b"ANDROID!":
        die(f"{path} is not an Android boot image (magic {raw[:8]!r})")
    hdr_version = struct.unpack_from("<I", raw, 0x28)[0]
    kernel_size = struct.unpack_from("<I", raw, 0x08)[0]
    if hdr_version < 3:
        die(f"boot header v{hdr_version}: kernel offset is not 0x1000, port manually")
    kernel = raw[PAGE:PAGE + kernel_size]
    kernel = decompress_auto(kernel, "kernel")
    if kernel[0x38:0x3C] != b"ARM\x64":
        problems.append("kernel payload has no ARM64 Image magic at 0x38")
    else:
        text_offset, image_size, flags = struct.unpack_from("<QQQ", kernel, 0x08)
        note(f"[img] boot v{hdr_version}  kernel={len(kernel)}B  "
             f"text_offset=0x{text_offset:x} image_size=0x{image_size:x} flags=0x{flags:x}")
        if text_offset != 0:
            problems.append(f"text_offset=0x{text_offset:x} != 0: recompute "
                            "P0_KERNEL_PHYS_LOAD from sboot.bin, do not assume 0x80000000")
    kpath = out / "kernel"
    kpath.write_bytes(kernel)
    return kpath, kernel


def extract_btf(image: bytes, out: Path) -> Path | None:
    prefix = b"\x9f\xeb\x01\x00"
    hits: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = image.find(prefix, cursor)
        if start < 0:
            break
        cursor = start + 1
        if start + 24 > len(image):
            continue
        magic, version, flags, header_len, type_off, type_len, str_off, str_len = \
            struct.unpack_from("<HBBIIIII", image, start)
        if magic != 0xEB9F or version != 1 or flags != 0 or header_len < 24:
            continue
        payload_len = max(type_off + type_len, str_off + str_len)
        end = start + header_len + payload_len
        str_start = start + header_len + str_off
        if end > len(image) or str_start >= end or image[str_start] != 0:
            continue
        hits.append((start, end))
    if len(hits) != 1:
        problems.append(f"expected exactly one raw BTF blob, found {len(hits)} "
                        "(no BTF -> the SM-A155N no-BTF procedure applies)")
        return None
    start, end = hits[0]
    note(f"[btf] raw blob [0x{start:x}, 0x{end:x}) = {end - start} bytes")
    p = out / "vmlinux.btf"
    p.write_bytes(image[start:end])
    return p


# ---------------------------------------------------------------- ELF view --
class Elf:
    """Minimal ELF64 reader: symbols + vaddr->file-offset mapping."""

    def __init__(self, path: Path) -> None:
        self.raw = path.read_bytes()
        if self.raw[:4] != b"\x7fELF" or self.raw[4] != 2:
            die(f"{path} is not ELF64")
        e = "<" if self.raw[5] == 1 else ">"
        self.e = e
        e_shoff = struct.unpack_from(e + "Q", self.raw, 0x28)[0]
        e_shentsize = struct.unpack_from(e + "H", self.raw, 0x3A)[0]
        e_shnum = struct.unpack_from(e + "H", self.raw, 0x3C)[0]
        self.sections: list[dict] = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            name, stype, _flags, addr, off, size, link, _info, _align, entsize = \
                struct.unpack_from(e + "IIQQQQIIQQ", self.raw, base)
            self.sections.append(dict(name=name, type=stype, addr=addr, off=off,
                                      size=size, link=link, entsize=entsize))
        self.symbols: dict[str, tuple[int, int]] = {}
        self._ordered: list[tuple[int, str]] = []
        self._load_symbols()

    def _load_symbols(self) -> None:
        for s in self.sections:
            if s["type"] != 2:  # SHT_SYMTAB
                continue
            strtab = self.sections[s["link"]]
            entsize = s["entsize"] or 24
            count = s["size"] // entsize
            for i in range(count):
                base = s["off"] + i * entsize
                st_name, _info, _other, shndx, value, size = struct.unpack_from(
                    self.e + "IBBHQQ", self.raw, base)
                if st_name == 0 or shndx == 0:
                    continue
                name = self._cstr_at(strtab["off"] + st_name)
                if not name:
                    continue
                prev = self.symbols.get(name)
                if prev is None or (prev[0] == 0 and value):
                    self.symbols[name] = (value, size)
        self._ordered = sorted((v, k) for k, (v, _s) in self.symbols.items() if v)

    def _cstr_at(self, off: int) -> str:
        end = self.raw.find(b"\x00", off)
        if end < 0:
            return ""
        return self.raw[off:end].decode(errors="replace")

    def sym(self, name: str) -> int | None:
        got = self.symbols.get(name)
        return got[0] if got else None

    def off(self, name: str, base: int) -> int | None:
        v = self.sym(name)
        return None if v is None else v - base

    def vaddr_to_off(self, addr: int) -> int | None:
        for s in self.sections:
            if s["type"] == 8:  # SHT_NOBITS
                continue
            if s["addr"] and s["addr"] <= addr < s["addr"] + s["size"]:
                return s["off"] + (addr - s["addr"])
        return None

    def read(self, addr: int, n: int) -> bytes:
        off = self.vaddr_to_off(addr)
        if off is None:
            die(f"vaddr 0x{addr:x} is not file-backed in the recovered ELF")
        return self.raw[off:off + n]

    def q(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def cstr(self, addr: int) -> str:
        off = self.vaddr_to_off(addr)
        if off is None:
            return ""
        return self._cstr_at(off)

    def nearest(self, addr: int) -> str:
        lo, hi = 0, len(self._ordered) - 1
        best = ""
        while lo <= hi:
            mid = (lo + hi) // 2
            if self._ordered[mid][0] <= addr:
                best = self._ordered[mid][1]
                lo = mid + 1
            else:
                hi = mid - 1
        return best


# ------------------------------------------------------------------- BTF ----
def dump_btf_structs(btf: Path, out: Path) -> dict[str, dict]:
    bpftool = shutil.which("bpftool")
    if not bpftool:
        problems.append("bpftool not on PATH: struct layout offsets are missing")
        return {}
    p = subprocess.run([bpftool, "btf", "dump", "file", str(btf), "format", "raw"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        problems.append(f"bpftool btf dump failed: {p.stderr.strip()[:200]}")
        return {}
    (out / "vmlinux-btf.raw").write_text(p.stdout)
    structs: dict[str, dict] = {}
    current: dict | None = None
    for line in p.stdout.splitlines():
        m = re.match(r"^\[(\d+)\]\s+(STRUCT|UNION)\s+'([\w\.]+)'\s+size=(\d+)", line)
        if m:
            current = {"size": int(m.group(4)), "members": {}}
            structs[m.group(3)] = current
            continue
        if line.startswith("["):
            current = None
            continue
        m = re.match(r"^\s+'([\w\.]+)'\s+type_id=\d+\s+bits_offset=(\d+)", line)
        if m and current is not None:
            bits = int(m.group(2))
            if bits % 8:
                problems.append(f"{m.group(1)} is not byte-aligned ({bits} bits)")
            else:
                current["members"][m.group(1)] = bits // 8
    return structs


# ------------------------------------------------------- symbol derivations --
def derive_worker_caller(elf: Elf, base: int, elf_path: Path) -> int | None:
    start = elf.sym("worker_thread")
    size = elf.symbols.get("worker_thread", (0, 0))[1]
    if not start or not size:
        problems.append("worker_thread symbol missing: SLIDE_TRACEFS_WORKER_CALLER_OFF unresolved")
        return None
    code = elf.read(start, size)
    target = elf.sym("schedule") or elf.sym("__schedule")
    if not target:
        problems.append("schedule symbol missing: cannot locate bl schedule")
        return None
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM  # type: ignore

        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for insn in md.disasm(code, start):
            if insn.mnemonic == "bl" and insn.operands and \
                    insn.operands[0].imm == target:
                return (insn.address + insn.size) - base
    except Exception:
        pass
    dis = shutil.which("llvm-objdump") or shutil.which("objdump")
    if not dis:
        problems.append("no capstone/llvm-objdump: disassemble worker_thread by hand")
        return None
    p = subprocess.run([dis, "-d", "--no-show-raw-insn", str(elf_path)], capture_output=True, text=True)
    addr = None
    for line in p.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+bl\s+0x([0-9a-f]+)", line)
        if m and int(m.group(2), 16) == target:
            addr = int(m.group(1), 16)
    return None if addr is None else addr - base


def derive_event_id(elf: Elf, override: int | None) -> int | None:
    if override is not None:
        return override
    start = elf.sym("__start_ftrace_events")
    ev = elf.sym("__event_sched_blocked_reason")
    if not start or not ev:
        problems.append("__start_ftrace_events/__event_sched_blocked_reason missing: "
                        "pass --trace-event-id from `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`")
        return None
    index = (ev - start) // 8
    return TRACE_LAST_TYPE_ANDROID_6_1 + index


def derive_nfulnl_name(elf: Elf, base: int) -> int | None:
    obj = elf.sym("nfulnl_logger")
    if not obj:
        problems.append("nfulnl_logger missing: SLIDE_NFULNL_LOGGER_NAME_OFF unresolved")
        return None
    name_ptr = elf.q(obj)
    got = elf.cstr(name_ptr)
    if got != "nfnetlink_log":
        problems.append(f"nfulnl_logger->name deref gave {got!r}, expected 'nfnetlink_log'")
        return None
    return name_ptr - base


def derive_bootid_entry(elf: Elf, structs: dict, base: int) -> tuple[int, int] | None:
    table = elf.sym("random_table")
    ct = structs.get("ctl_table")
    if not table or not ct:
        problems.append("random_table/ctl_table missing: SLIDE_RANDOM_TABLE_BOOT_ID_* unresolved")
        return None
    size = ct["size"]
    off_name = ct["members"].get("name")
    off_data = ct["members"].get("data")
    if off_name is None or off_data is None:
        problems.append("ctl_table.name/data offsets missing from BTF")
        return None
    for i in range(64):
        entry = table + i * size
        try:
            name_ptr = elf.q(entry + off_name)
            name = elf.cstr(name_ptr) if name_ptr else ""
        except SystemExit:
            break
        if name == "boot_id":
            note(f"[bootid] random_table[{i}] = boot_id at 0x{entry - base:x}")
            return (entry + off_data) - base, i
    problems.append("random_table[] has no 'boot_id' entry (walk its .name pointers by hand)")
    return None


# -------------------------------------------------------- p0 fingerprint ----
def p0_table(image: bytes, out: Path) -> tuple[int, list[list[int]]]:
    rows = []
    slide = 0
    truncated = False
    while slide <= SLIDE_MAX:
        cells = []
        for off in P0_ROW_OFFSETS:
            pos = slide + off
            if pos + 8 > len(image):
                truncated = True
                cells.append(0)
            else:
                cells.append(struct.unpack_from("<Q", image, pos)[0])
        rows.append(cells)
        slide += SLIDE_STEP
    if truncated:
        problems.append("kernel image shorter than the P0 slide range: table rows past "
                        f"0x{len(image):x} are zero-filled -- verify P0_SLIDE_MAX on hardware")
    lines = [
        "/* generated by port_a55.py -- Root-My-Galaxy-Payloads/docs/PORTING.md step 5",
        " * row = candidate slide, cols = LE qwords at page offsets",
        f" * {', '.join(hex(o) for o in P0_ROW_OFFSETS)}",
        " * VERIFY against an existing src/targets/*/p0_fingerprint.h shape before use. */",
        "#pragma once",
        "#include <stdint.h>",
        f"#define P0_ROW_OFFSETS {{ {', '.join(hex(o) for o in P0_ROW_OFFSETS)} }}",
        f"#define P0_SLIDE_STEP 0x{SLIDE_STEP:x}ULL",
        f"#define P0_SLIDE_MAX  0x{SLIDE_MAX:x}ULL",
        "static const uint64_t p0_fingerprint[][8] = {",
    ]
    for slide, row in zip(range(0, SLIDE_MAX + 1, SLIDE_STEP), rows):
        cells = ", ".join(f"0x{v:016x}ULL" for v in row)
        lines.append(f"    {{{cells}}}, /* slide 0x{slide:06x} */")
    lines.append("};")
    p = out / "p0_fingerprint.h"
    p.write_text("\n".join(lines) + "\n")
    return len(rows), rows


# ----------------------------------------------------------------- emit -----
def emit_target_h(out: Path, info: dict) -> Path:
    def d(name: str, value) -> str:
        if value is None:
            problems.append(f"{name} unresolved")
            return f"/* TODO {name}: unresolved */\n#define {name} 0ULL"
        if isinstance(value, int):
            return f"#define {name} 0x{value:016x}ULL"
        return f"#define {name} {value}"

    L = ["/* generated by port_a55.py -- firmware-bound, one file per build */",
         "#pragma once", "#include <stdint.h>", "",
         "/* --- firmware identity --- */"]
    for k, v in info["identity"].items():
        L.append(f'#define {k} "{v}"')
    L += ["", "/* --- physical / direct map --- */"]
    const_defaults = {"P0_PAGE_OFFSET": P0_PAGE_OFFSET, "P0_PHYS_OFFSET": P0_PHYS_OFFSET,
                      "DIRECT_MAP_BASE": DIRECT_MAP_BASE, "VMEMMAP_START": VMEMMAP_START}
    for k in ("KIMAGE_TEXT_BASE", "P0_PAGE_OFFSET", "P0_PHYS_OFFSET",
              "P0_KERNEL_PHYS_LOAD", "DIRECT_MAP_BASE", "VMEMMAP_START",
              "P0_ORACLE_PROBE_OFFSET"):
        L.append(d(k, info.get(k, const_defaults.get(k))))
    L += ["", "/* --- text-relative symbol offsets --- */"]
    for k, v in info["symbols"].items():
        L.append(d(k, v))
    L += ["", "/* --- slide oracle --- */"]
    for k in ("SLIDE_TRACEFS_EVENT_ID", "SLIDE_TRACEFS_WORKER_CALLER_OFF",
              "SLIDE_PSELECT_WORD_SHIFT", "SLIDE_NFULNL_LOGGER_NAME_OFF",
              "SLIDE_NFULNL_LOGGER_OBJECT_OFF",
              "SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF", "SLIDE_SYSCTL_BOOTID_OFF"):
        L.append(d(k, info.get(k)))
    L += ["", "/* --- struct layout (BTF) --- */"]
    for k, v in info["layout"].items():
        L.append(d(k, v) if not isinstance(v, int) or v > 0xff else f"#define {k} 0x{v:x}")
    p = out / "target.h"
    p.write_text("\n".join(L) + "\n")
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", required=True, type=Path, help="boot.img or boot.img.lz4")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--pda", default="", help="AP/PDA build id, e.g. A556EXXU4BYH2")
    ap.add_argument("--model", default="SM-A556E")
    ap.add_argument("--device", default="a55x")
    ap.add_argument("--trace-event-id", type=int, default=None)
    ap.add_argument("--kernel-phys-load", default=None,
                    help="P0_KERNEL_PHYS_LOAD from sboot.bin (hex)")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    note(f"[*] boot={args.boot} out={args.out}")

    kpath, kernel = unpack_boot(args.boot, args.out)
    note(f"[img] kernel sha256={hashlib.sha256(kernel).hexdigest()}")

    elf_path = args.out / "vmlinux.elf"
    if not elf_path.exists():
        v2e = shutil.which("vmlinux-to-elf")
        if not v2e:
            die("vmlinux-to-elf not on PATH: `pip install vmlinux-to-elf`")
        note("[*] vmlinux-to-elf ...")
        p = subprocess.run([v2e, str(kpath), str(elf_path)], capture_output=True, text=True)
        if p.returncode != 0 or not elf_path.exists():
            die(f"vmlinux-to-elf failed: {(p.stderr or p.stdout).strip()[:400]}")

    elf = Elf(elf_path)
    base = elf.sym("_text") or elf.sym("_stext")
    if not base:
        die("no _text symbol: kallsyms recovery failed (try a newer vmlinux-to-elf)")
    note(f"[elf] _text = 0x{base:x}  symbols={len(elf.symbols)}")

    btf = extract_btf(kernel, args.out)
    structs = dump_btf_structs(btf, args.out) if btf else {}

    info: dict = {"identity": {
        "TARGET_MODEL": args.model,
        "TARGET_DEVICE": args.device,
        "TARGET_PDA": args.pda or "UNKNOWN",
    }}
    info["KIMAGE_TEXT_BASE"] = base
    info["P0_PAGE_OFFSET"] = P0_PAGE_OFFSET
    info["P0_PHYS_OFFSET"] = P0_PHYS_OFFSET
    info["P0_KERNEL_PHYS_LOAD"] = (int(args.kernel_phys_load, 16)
                                 if args.kernel_phys_load else None)
    info["DIRECT_MAP_BASE"] = DIRECT_MAP_BASE
    info["VMEMMAP_START"] = VMEMMAP_START
    info["P0_ORACLE_PROBE_OFFSET"] = None  # from the payload's own definition

    syms: dict[str, int | None] = {}
    for macro, sname, extra in SYMBOL_MACROS:
        syms[macro] = None if (v := elf.off(sname, base)) is None else v + extra
        if syms[macro] is None:
            problems.append(f"{macro}: symbol '{sname}' missing from kallsyms")
    info["symbols"] = syms

    info["SLIDE_TRACEFS_EVENT_ID"] = derive_event_id(elf, args.trace_event_id)
    info["SLIDE_TRACEFS_WORKER_CALLER_OFF"] = derive_worker_caller(elf, base, elf_path)
    info["SLIDE_NFULNL_LOGGER_NAME_OFF"] = derive_nfulnl_name(elf, base)
    info["SLIDE_PSELECT_WORD_SHIFT"] = None
    problems.append("SLIDE_PSELECT_WORD_SHIFT needs manual fd_set/rt_mutex_waiter "
                    "stack analysis; feasible only when the derived shift <= 3")

    layout: dict[str, int | None] = {}
    for st, fields in STRUCT_FIELDS.items():
        got = structs.get(st)
        if not got:
            problems.append(f"struct {st} missing from BTF")
            continue
        layout[f"SIZEOF_{st.upper()}"] = got["size"]
        for f in fields:
            layout[f"{st.upper()}_{f.upper()}"] = got["members"].get(f)
    if "miscdevice" in structs and layout.get("MISCDEVICE_FOPS") is not None:
        misc = elf.off("ashmem_misc", base)
        if misc is not None:
            info["symbols"]["ASHMEM_MISC_FOPS_OFF"] = misc + layout["MISCDEVICE_FOPS"]
    if "selinux_state" in structs and layout.get("SELINUX_STATE_ENFORCING") is not None:
        sstate = elf.off("selinux_state", base)
        if sstate is not None:
            info["symbols"]["SELINUX_ENFORCING_OFF"] = sstate + layout["SELINUX_STATE_ENFORCING"]
    bootid = derive_bootid_entry(elf, structs, base)
    if bootid:
        info["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"] = bootid[0]
    info["layout"] = layout

    rows, _ = p0_table(kernel, args.out)
    note(f"[p0] {rows} rows written")

    th = emit_target_h(args.out, info)
    report = args.out / "port-report.md"
    report.write_text("\n".join([
        f"# {args.model} / {args.pda or 'UNKNOWN'} port report",
        "",
        f"- kernel sha256: `{hashlib.sha256(kernel).hexdigest()}`",
        f"- boot sha256:   `{hashlib.sha256(Path(args.boot).read_bytes()).hexdigest()}`",
        f"- _text:         `0x{base:x}`",
        f"- BTF:           `{'yes' if btf else 'no'}`",
        f"- structs found: `{', '.join(sorted(structs)) or 'none'}`",
        "",
        "## unresolved / manual",
        *([f"- {p}" for p in problems] or ["- (none)"]),
        "",
        "Next: read `uname -r` on the phone, put it in `TARGET_KERNEL_RELEASE`,",
        "build with `make TARGET=a55x-<PDA> ANDROID_NDK_HOME=... release`,",
        "then build the matching `kernelsu.ko` with vermagic",
        "`<uname -r> SMP preempt mod_unload modversions aarch64` and",
        "`CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y`.",
    ]) + "\n")

    note(f"[ok] {th}")
    note(f"[ok] {report}")
    for k in ("KIMAGE_TEXT_BASE", "SLIDE_TRACEFS_EVENT_ID",
              "SLIDE_TRACEFS_WORKER_CALLER_OFF", "SLIDE_NFULNL_LOGGER_NAME_OFF"):
        v = info.get(k)
        note(f"     {k} = {('0x%x' % v) if isinstance(v, int) else 'UNRESOLVED'}")
    if problems:
        note(f"[!] {len(problems)} unresolved item(s) -- see {report.name}")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
