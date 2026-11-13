# droid-lkm-ins

A head-only loader and remover for Linux kernel modules on Android, able to load
a module that references symbols the kernel does not export.

> [!WARNING]
> **This project is AI-generated software.**
>
> It was written by an AI coding agent under human direction. Treat it as
> untrusted code: read it before you run it, especially before running it with
> root on a device you care about.  Loading a kernel module is the most
> privileged operation on an Android device short of flashing a partition, and a
> mistake here does not produce an error message, it produces a panic.
>
> Yes, this warning exists because "AI slop" is a real failure mode. The code is
> not exempt from review just because a test suite is green.

## What it is

Two things in one small piece of C:

1. **`lkm_bind.h`** — bind a `.ko`'s undefined symbols and hand it to the
   kernel's own `init_module(2)`.
2. **`lkmctl`** — the command-line front end for the above.

It is deliberately *not* a full module loader.  See "Why it is small" below.

## Why it is small

The obvious design — copy the `.ko` into kernel memory, apply relocations
yourself, run `module_init` — is the wrong shape, and this project started down
that path before checking how the existing tools do it.

[KernelSU]'s `ksuinit` (`userspace/ksuinit/src/lib.rs`) and [APatch]'s `apd`
(`apd/src/insmod.rs`, an explicit port of KernelSU's) do something far smaller:

1. walk the ELF symtab;
2. for every `SHN_UNDEF` symbol, rewrite the entry in place to
   `st_value = <kernel address>`, `st_shndx = SHN_ABS`;
3. call `init_module(2)` with the patched image.

The kernel then does the real work: executable module memory, relocation,
`CONFIG_STRICT_MODULE_RWX`, lifecycle, `/sys/module`, refcounting and removal.
Re-implementing that inside a module is how you end up with pinned modules, hooks
that outlive their text, and refcounts that never drain — all of which this
family of loading code has had to fight before.

So this repository does the small thing, and lets the kernel keep the big thing.

## What the bind has to get right

Each of these was learned from the references and is covered by the tests:

- **`kptr_restrict`.** `/proc/kallsyms` reports zero addresses while it is 2 (and
  for non-root while it is 1).  It is lowered for the duration of the read and
  restored afterwards, including on the error paths.
- **Stop at module symbols.** The file lists kernel symbols first and module
  symbols after.  Reading stops at the first line carrying a module name, so a
  module's symbol can never shadow a kernel symbol.
- **Name suffixes.** `foo$variant`, `foo.llvm.1234` and a trailing `.cfi_jt` are
  folded back to `foo` before lookup.
- **Do not fabricate.** A symbol that cannot be resolved is counted and reported;
  it is left `SHN_UNDEF` for the kernel to resolve the ordinary (exported) way.
  An all-zero kallsyms table is an error, never a table of address 0.

## Usage

```
lkmctl insmod <module.ko> [param=value ...]
lkmctl bind   <module.ko>          # rewrite a copy, do not load
lkmctl check  <module.ko>          # report what would be bound
```

Requires root (or a domain allowed to load modules), plus readable addresses from
`/proc/kallsyms`.

## What this does *not* replace

It replaces the **load/unload capability** of [KernelSU]'s `ksud` and
[APatch]'s `apd`, not those tools.  `ksud` additionally manages installed
modules, applies SELinux policy, handles `su` compatibility and installs ZIPs;
`apd` has its own daemon and KernelPatch integration.  If you need any of that,
keep using them.

Two paths exist in `ksuinit`: local `/proc/kallsyms` resolution, and a resolver
that asks the KernelSU driver for addresses.  This project implements the first.
On the kernels it has been tested against, every symbol the modules needed was
visible in `/proc/kallsyms` (verified: a 678-symbol module binds with zero
unresolved), so the driver path was not required.  On a kernel where some symbol
is genuinely hidden from `/proc/kallsyms`, this loader will report it and fail
rather than pretend.

## Building

```
make            # static library + host tests
make shared     # prebuilt shared libraries (host + aarch64)
make test       # run the host test suite
```

The header is the deliverable; the library targets exist so a consumer can link
a prebuilt `.so` instead of compiling the implementation.

## ABI

`LKM_BIND_ABI_VERSION` / `lkm_bind_abi_version()`.  A consumer that loads the
prebuilt shared library must compare the two before use: a mismatch means the
struct layouts may differ.

## References

- [KernelSU] — `userspace/ksuinit/src/lib.rs` (`load_module`,
  `kernel_symbols_iter`), and `kernel/preinit/runner/runner.c` for the in-kernel
  variant.
- [APatch] — `apd/src/insmod.rs`, a direct port of the above.

Both are GPL-3.0; this project is GPL-2.0-only and shares no code with them, only
the approach.

[KernelSU]: https://github.com/tiann/KernelSU
[APatch]: https://github.com/bmax121/APatch
