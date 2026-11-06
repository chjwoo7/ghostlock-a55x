"""Offline self-test for port_a55.Elf / derive_* / p0_table / emit_target_h.

Builds a synthetic ELF64 + kernel image with known values and checks that the
derivations come back correct. Run: python test_port.py
"""

import struct
import sys
from pathlib import Path

import port_a55 as P

BASE = 0xFFFFFFC008000000
TEXT_OFF = 0x1000
DATA_OFF = 0x1100
DATA_SIZE = 0x600
SYMTAB_OFF = 0x1800
STRTAB_OFF = 0x1A00


def cstr_table(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = b"\x00"
    offs = {}
    for n in names:
        offs[n] = len(blob)
        blob += n.encode() + b"\x00"
    return blob, offs


def build_elf(path: Path) -> None:
    names = ["_text", "worker_thread", "schedule", "nfulnl_logger",
             "random_table", "sysctl_bootid", "ashmem_misc", "selinux_state"]
    strtab, offs = cstr_table(names)
    syms = [
        (0, 0, 0, 0),
        (offs["_text"], 1, BASE, 0),
        (offs["worker_thread"], 1, BASE + 0x40, 0x20),
        (offs["schedule"], 1, BASE + 0x90, 0),
        (offs["nfulnl_logger"], 2, BASE + 0x1000, 8),
        (offs["random_table"], 2, BASE + 0x1100, 0x40 * 8),
        (offs["sysctl_bootid"], 2, BASE + 0x1500, 16),
        (offs["ashmem_misc"], 2, BASE + 0x1580, 0x40),
        (offs["selinux_state"], 2, BASE + 0x15A0, 0x20),
    ]
    symtab = b"".join(
        struct.pack("<IBBHQQ", name, (2 if i else 0), 0, shndx, value, size)
        for i, (name, shndx, value, size) in enumerate(syms)
    )

    data = bytearray(DATA_SIZE)
    struct.pack_into("<Q", data, 0x1000 - 0x1000, BASE + 0x1200)      # nfulnl_logger->name
    data[0x1200 - 0x1000:0x1200 - 0x1000 + 15] = b"nfnetlink_log\x00"
    for i in range(8):                                                # random_table[]
        entry = 0x1100 + i * 0x40 - 0x1000
        if i == 3:
            struct.pack_into("<Q", data, entry, BASE + 0x1400)        # -> "boot_id"
            struct.pack_into("<Q", data, entry + 8, BASE + 0x1500)    # -> sysctl_bootid
    data[0x1400 - 0x1000:0x1400 - 0x1000 + 8] = b"boot_id\x00"

    text = bytearray(0x100)
    # bl schedule from worker_thread+0x10
    delta = (BASE + 0x90) - (BASE + 0x40 + 0x10)
    struct.pack_into("<I", text, 0x10, 0x94000000 | ((delta >> 2) & 0x03FFFFFF))

    shdrs = [b"\x00" * 64]

    def shdr(name, stype, addr, off, size, link=0, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, stype, 0, addr, off, size, link, 0, 8, entsize)

    shdrs.append(shdr(0, 1, BASE, TEXT_OFF, len(text)))
    shdrs.append(shdr(0, 1, BASE + 0x1000, DATA_OFF, DATA_SIZE))
    shdrs.append(shdr(0, 2, 0, SYMTAB_OFF, len(symtab), 4, 24))
    shdrs.append(shdr(0, 3, 0, STRTAB_OFF, len(strtab)))

    out = bytearray(STRTAB_OFF + len(strtab))
    out[0:16] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    struct.pack_into("<HHI", out, 16, 2, 183, 1)
    struct.pack_into("<Q", out, 24, BASE)
    struct.pack_into("<Q", out, 32, 0)          # phoff
    struct.pack_into("<Q", out, 40, 0x100)      # shoff
    struct.pack_into("<HHI", out, 52, 64, 0, 0)
    struct.pack_into("<HHH", out, 58, 64, len(shdrs), 0)
    out[0x100:0x100 + 64 * len(shdrs)] = b"".join(shdrs)
    out[TEXT_OFF:TEXT_OFF + len(text)] = text
    out[DATA_OFF:DATA_OFF + DATA_SIZE] = data
    out[SYMTAB_OFF:SYMTAB_OFF + len(symtab)] = symtab
    out[STRTAB_OFF:STRTAB_OFF + len(strtab)] = strtab
    path.write_bytes(out)


def main() -> int:
    root = Path("T_selftest")
    root.mkdir(exist_ok=True)
    elf_file = root / "vmlinux.elf"
    build_elf(elf_file)

    elf = P.Elf(elf_file)
    base = elf.sym("_text")
    assert base == BASE, hex(base)
    assert elf.off("nfulnl_logger", base) == 0x1000

    name_off = P.derive_nfulnl_name(elf, base)
    assert name_off == 0x1200, hex(name_off)

    structs = {"ctl_table": {"size": 0x40, "members": {"name": 0x0, "data": 0x8}}}
    bootid = P.derive_bootid_entry(elf, structs, base)
    assert bootid is not None and bootid[0] == 0x11C8, bootid
    assert elf.q(BASE + bootid[0]) == BASE + 0x1500  # .data ptr -> sysctl_bootid

    kernel = bytearray(0x2000)
    kernel[0x38:0x3C] = b"ARM\x64"
    (root / "kernel").write_bytes(kernel)
    rows, table = P.p0_table(bytes(kernel), root)
    assert rows == (P.SLIDE_MAX // P.SLIDE_STEP) + 1, rows
    assert (root / "p0_fingerprint.h").exists()

    info = {"identity": {"TARGET_PDA": "TEST"}, "KIMAGE_TEXT_BASE": base,
            "symbols": {"ASHMEM_MISC_FOPS_OFF": 0x1590},
            "layout": {"SIZEOF_TASK_STRUCT": 0x2a00}}
    header = P.emit_target_h(root, info)
    text = header.read_text()
    assert "0x00000000ffffff" in text or "ffffffc008000000" in text, text[:400]
    print("selftest OK ->", header)
    return 0


if __name__ == "__main__":
    sys.exit(main())
