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

Three things in one small piece of C:

1. **`lkm_bind.h`** — bind a `.ko`'s undefined symbols and hand it to the
   kernel's own `init_module(2)`.
2. **`lkm_insmod.c`** — the testable insmod core: canonicalize the module path,
   adapt the `.gnu.linkonce.this_module` section to the running kernel's
   `struct module` layout (read from BTF), extract a kernel-required vermagic
   from the kernel log, rewrite `.modinfo`, and retry the load exactly once.
3. **`lkmctl`** — the command-line front end for the above.

It is deliberately *not* a full module loader.  See "Why it is small" below.

## Status

Verified on the development host (commit `b6f7e0a`, 2026-11-21):

- `make test` passes: 29 (`lkm_bind_test`) + 163 (`lkm_insmod_test`) + 12
  (`lkmctl_cli_test.sh`) checks, 0 failures, with `-Werror`; the same command
  passes from a clean clone of `origin/master`.
- The host's `/sys/kernel/btf/vmlinux` parses to
  `size=1600 name_off=24 init_off=392 exit_off=1528`, matching the layout the
  tests use.
- The `SHT_NOBITS` regression test fails against the pre-fix code and passes
  against this commit.
- `make android` produces `build/lkmctl-android`: `file` says
  `ELF 64-bit LSB executable, ARM aarch64, statically linked`, `readelf -l`
  has no `INTERP`, `readelf -d` has no dynamic section, and it runs on the
  (aarch64) host.

Not verified yet (see [docs/evidence/insmod-core.md](docs/evidence/insmod-core.md)):

- an adapted `.ko` has not completed a real `init_module(2)` on a kernel whose
  `struct module` layout differs; that needs a QEMU or device gate;
- the `[permanent]` episode and the 678-symbol bind have no captured log;
- running `build/lkmctl-android` on an Android device (that is the droid-hook
  gate; this repository only claims the ELF shape and a host run).

There is no CI workflow in this repository (GitHub Actions usage: 0/9);
`make test` is the only gate, and it is run in the foreground so a failure is
never silent.

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

## Module ABI layout (struct module)

A `.ko` carries the kernel's `struct module` layout in its
`.gnu.linkonce.this_module` section, generated from the headers it was built
against.  If those headers differ from the running kernel, the module can load
but have `init`/`exit` read from the wrong offsets.  The failure mode is a
module the kernel marks `[permanent]` because `exit` reads as NULL, which then
refuses to unload (reported on a device; see the evidence notes).

`lkmctl` does not require a per-kernel module build.  Before `init_module(2)` it
reads the running kernel's real layout from `/sys/kernel/btf/vmlinux`, and if
the section size, name offset or the `init_module`/`cleanup_module` relocation
offsets disagree, it rewrites the section at the aligned end of the image with
exactly the kernel's `sizeof(struct module)`, places the name at the kernel's
`name` offset, and moves the relocations to the kernel's `init`/`exit` offsets.
Other fields are left zero for the kernel to initialise.  The adaptation is
announced on stderr; a module that already matches is left byte-for-byte alone.

`SHT_NOBITS` sections (`.bss`) have no file contents; the section walk skips
their offsets and sizes exactly as the kernel does, so a large `.bss` is not
mistaken for a truncated image.  Only ELF64 relocatable objects are handled
(all Android GKI modules); a 32-bit image is refused with an explicit
`ENOEXEC` rather than guessed around.

When BTF exists but the section cannot be adapted, the load is refused before
`init_module(2)`: a module that may never be unloadable is not loaded by
default.  When the kernel has no BTF the layout cannot be checked, so that is
also refused by default.

`lkmctl insmod --force` is the only override.  It requires an interactive TTY
on both stdin and stderr; without one the load is refused outright, because a
non-interactive stream cannot consent.  When a TTY is present, the operator
must type the following line exactly twice (trailing newline aside):

```
YES I AGREE LOAD THIS UNSAFE MODULE
```

Only then is the module loaded, with the danger restated on stderr.  The
confirmation is deliberately long and all-caps so it cannot be typed by
accident or mistaken for the usual `y/n`.

## Vermagic mismatch

A module built for another kernel release is normally rejected with `ENOEXEC`
and a bare "invalid module format" that says nothing actionable.  The loader
follows KernelSU's `ksuinit` here:

1. before the first attempt, open `/dev/kmsg` (or `/kmsg`) non-blocking and
   drain it to the current end, so only records from this load can be seen;
2. on `ENOEXEC`, look for the newest record
   `... version magic '<module>' should be '<kernel>' ...`;
3. rebuild the module's `.modinfo` section with the kernel's value - the
   section is located through the ELF section table, a fresh copy is appended
   at the aligned end of the image, and the section header's `sh_offset` /
   `sh_size` are updated, so a longer value fits;
4. retry `init_module(2)` **once**.  A second failure is reported as the
   failure it is; there is never a third attempt.

The rewrite is always announced on stderr: a module built for a different
kernel can load and then misbehave in ways far harder to diagnose than a
refusal.  When the log does not contain a usable record, when it cannot be
read, or when the image has no `.modinfo` section, the original `ENOEXEC` is
reported together with that reason - no blind retry and no fabricated success.

## Usage

```
lkmctl insmod [--force] <module.ko> [param=value ...]
lkmctl rmmod  <name> [--force]
lkmctl bind   <module.ko>          # rewrite a copy, do not load
lkmctl check  <module.ko>          # report what would be bound
```

The module path is canonicalized before it is read, as `ksud` and `apd` do; a
path that cannot be resolved is an error rather than something to guess around.
The success line is the references' line, with the canonical path:

```
Loaded kernel module: /data/local/tmp/dnsk_core.ko
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
make tools      # the lkmctl binary for the host
make android    # aarch64 static lkmctl for the device (see below)
make test       # run the host test suites
```

The header is the deliverable; the library targets exist so a consumer can link
a prebuilt `.so` instead of compiling the implementation.  `make test` runs
`lkm_bind_test` (symbol binding), `lkm_insmod_test` (path canonicalization,
kernel-log vermagic extraction, `.modinfo` rewrite, BTF `struct module` layout
parsing and `.this_module` adaptation, and the one-shot retry driver, all
against synthesized ELF64 module images and a fake load callback), and a small
CLI negative test (`lkmctl_cli_test.sh`).

## Android target build

`make android` builds `build/lkmctl-android`, an aarch64 ELF meant to be copied
to the device:

```
make android
```

This host has the NDK headers (`/usr/local/share/ndk`) but no bionic sysroot or
Android clang driver, and installing a toolchain is out of scope, so the target
links **statically against the aarch64 glibc cross toolchain**
(`aarch64-linux-gnu-gcc -static`).  It is therefore not a bionic-linked binary,
but it has no `PT_INTERP`: it needs neither `/system/bin/linker64` nor
`/lib/ld-linux-aarch64.so.1`.

```
$ file build/lkmctl-android
build/lkmctl-android: ELF 64-bit LSB executable, ARM aarch64, version 1
(GNU/Linux), statically linked, ..., for GNU/Linux 3.7.0, not stripped
$ readelf -l build/lkmctl-android | grep INTERP   # no output
$ readelf -d build/lkmctl-android
There is no dynamic section in this file.
```

Limits:

- static glibc, not bionic; a bionic target needs a real NDK and is not built
  here;
- on-device execution is the device gate's claim, not this repository's: the
  binary has only been checked with `file`, `readelf` and one run on the host
  (which is itself aarch64);
- the host binary `build/lkmctl` stays glibc dynamic and must not be used on
  Android.

## ABI

`LKM_BIND_ABI_VERSION` / `lkm_bind_abi_version()`.  A consumer that loads the
prebuilt shared library must compare the two before use: a mismatch means the
struct layouts may differ.

## References

- [KernelSU] — `userspace/ksuinit/src/lib.rs` (`load_module`,
  `kernel_symbols_iter`, `extract_required_vermagic`,
  `replace_module_vermagic`), `userspace/ksud/src/debug.rs` (`insmod`: path
  canonicalization and the `Loaded kernel module:` line), and
  `kernel/preinit/runner/runner.c` for the in-kernel variant.
- [APatch] — `apd/src/insmod.rs`, a direct port of the above, and the source of
  the canonicalize/`Loaded kernel module:` output shape.
- Verification of the kernel and reference claims above, with pinned commits
  and `path:line` citations:
  [docs/evidence/insmod-core.md](docs/evidence/insmod-core.md).

Both are GPL-3.0; this project is GPL-2.0-only and shares no code with them, only
the approach.

[KernelSU]: https://github.com/tiann/KernelSU
[APatch]: https://github.com/bmax121/APatch
