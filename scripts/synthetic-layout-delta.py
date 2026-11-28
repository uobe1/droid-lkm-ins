#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Move a module's struct-module layout to a second, known set.

The same-KMI QEMU gate needs a module whose .gnu.linkonce.this_module section
does not match the running kernel even though the module was built from the
same KMI.  This script produces that state reproducibly: it rewrites the
section's sh_size and the r_offset of the init_module / cleanup_module
relocations to the "other" values, and leaves everything else alone.

The values are the real ones a differently configured android16-6.12 kernel
was seen to use: 1584 bytes, init at 376, exit at 1512 (the gate's kernel uses
1600 / 392 / 1528).  The point is that the pair is fixed and reproducible,
not that it came from a particular build.

Usage:
  synthetic-layout-delta.py <in.ko> <out.ko> [--size N] [--init N] [--exit N]

Exits non-zero, with a reason, if the image is not an ELF64 relocatable object
or does not carry the section/relocations the gate asserts on.  After patching
it re-reads the file and asserts the new values, so a silent no-op is
impossible.
"""
import argparse
import struct
import sys

SHT_RELA = 4


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def read_elf(data):
    if len(data) < 64:
        fail("image is too short to be ELF")
    if data[:4] != b"\x7fELF":
        fail("not an ELF image")
    if data[4] != 2:
        fail(f"not ELF64 (class {data[4]})")
    if data[5] not in (1, 2):
        fail(f"bad ELF data encoding {data[5]}")
    le = data[5] == 1
    e = "<" if le else ">"
    shoff = struct.unpack_from(e + "Q", data, 40)[0]
    shentsize = struct.unpack_from(e + "H", data, 58)[0]
    shnum = struct.unpack_from(e + "H", data, 60)[0]
    shstrndx = struct.unpack_from(e + "H", data, 62)[0]
    if shoff == 0 or shnum == 0 or shentsize < 64:
        fail("no usable section header table")
    if shoff + shnum * shentsize > len(data):
        fail("section header table is outside the image")
    if shstrndx >= shnum:
        fail("extended section numbering is unsupported")
    return e, le, shoff, shentsize, shnum, shstrndx


def section(data, e, shoff, shentsize, index):
    h = shoff + index * shentsize
    sh_name = struct.unpack_from(e + "I", data, h)[0]
    sh_type = struct.unpack_from(e + "I", data, h + 4)[0]
    sh_offset = struct.unpack_from(e + "Q", data, h + 24)[0]
    sh_size = struct.unpack_from(e + "Q", data, h + 32)[0]
    sh_link = struct.unpack_from(e + "I", data, h + 40)[0]
    sh_entsize = struct.unpack_from(e + "Q", data, h + 56)[0]
    return {
        "hdr": h, "name": sh_name, "type": sh_type, "offset": sh_offset,
        "size": sh_size, "link": sh_link, "entsize": sh_entsize,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--size", type=int, default=1584)
    ap.add_argument("--init", type=int, default=376)
    ap.add_argument("--exit", type=int, default=1512)
    args = ap.parse_args()

    data = bytearray(open(args.src, "rb").read())
    e, _le, shoff, shentsize, shnum, shstrndx = read_elf(data)

    strtab = section(data, e, shoff, shentsize, shstrndx)
    names = {}
    for i in range(shnum):
        s = section(data, e, shoff, shentsize, i)
        o = s["name"]
        if o >= strtab["size"]:
            continue
        start = strtab["offset"] + o
        end = data.index(b"\0", start)
        names.setdefault(data[start:end].decode("utf-8", "replace"), i)

    tm_name = ".gnu.linkonce.this_module"
    rela_name = ".rela.gnu.linkonce.this_module"
    for want in (tm_name, rela_name):
        if want not in names:
            fail(f"module has no {want} section")
    tm = section(data, e, shoff, shentsize, names[tm_name])
    rela = section(data, e, shoff, shentsize, names[rela_name])

    if rela["type"] != SHT_RELA or rela["entsize"] < 24 or \
            rela["size"] % 24 != 0:
        fail("unusable this_module relocations")
    symtab = section(data, e, shoff, shentsize, rela["link"])
    strtab2 = section(data, e, shoff, shentsize, symtab["link"])

    def sym_name(index):
        st_name = struct.unpack_from(e + "I", data,
                                     symtab["offset"] + index * 24)[0]
        start = strtab2["offset"] + st_name
        return data[start:data.index(b"\0", start)].decode("utf-8", "replace")

    seen = {}
    for k in range(rela["size"] // 24):
        at = rela["offset"] + k * 24
        r_info = struct.unpack_from(e + "Q", data, at + 8)[0]
        name = sym_name(r_info >> 32)
        if name in ("init_module", "cleanup_module"):
            seen[name] = at

    for want in ("init_module", "cleanup_module"):
        if want not in seen:
            fail(f"module has no {want} relocation")

    old_size = tm["size"]
    old_init = struct.unpack_from(e + "Q", data, seen["init_module"])[0]
    old_exit = struct.unpack_from(e + "Q", data, seen["cleanup_module"])[0]

    struct.pack_into(e + "Q", data, tm["hdr"] + 32, args.size)
    struct.pack_into(e + "Q", data, seen["init_module"], args.init)
    struct.pack_into(e + "Q", data, seen["cleanup_module"], args.exit)
    open(args.dst, "wb").write(data)

    # Re-read and assert: a "successful" no-op would quietly prove nothing.
    check = bytearray(open(args.dst, "rb").read())
    e2, _, shoff2, ent2, _, _ = read_elf(check)
    tm2 = section(check, e2, shoff2, ent2, names[tm_name])
    rela2 = section(check, e2, shoff2, ent2, names[rela_name])
    got_size = struct.unpack_from(e2 + "Q", check, tm2["hdr"] + 32)[0]
    got_init = struct.unpack_from(e2 + "Q", check, seen["init_module"])[0]
    got_exit = struct.unpack_from(e2 + "Q", check, seen["cleanup_module"])[0]
    if (got_size, got_init, got_exit) != (args.size, args.init, args.exit):
        fail(f"patch did not take: {(got_size, got_init, got_exit)}")
    if rela2["size"] == 0:
        fail("relocations vanished")

    print(f"{args.src}: this_module size {old_size} -> {got_size}, "
          f"init {old_init} -> {got_init}, exit {old_exit} -> {got_exit}")


if __name__ == "__main__":
    main()
