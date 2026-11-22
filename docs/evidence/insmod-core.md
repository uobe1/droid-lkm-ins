# Evidence: insmod core (vermagic retry and `struct module` layout)

Status: 2026-11-21.  Records the first-party sources behind the kernel/ABI
claims in `README.md` and `src/lkm_insmod.c`, so a future reader does not have
to take this project's word for them.

Verification levels:

| level | meaning |
|---|---|
| A | source read at the pinned commit; exact `path:line` recorded |
| B | measured on this host against a real artifact |
| C | reproduced with a synthetic fixture or a failing/passing host test |
| D | not verified; the README says so instead of claiming it |

Pinned sources:

- AOSP 6.12.30 tree at `/usr/local/share/aosp-6.12.30`, commit
  `105b5745f1d771060aa9fb7f75821f69bb2298fd`; every path below was read with
  `git show HEAD:<path>` at that commit.
- KernelSU commit `2a60b2893b8d0d885d1ceff2287d8ad854f0e0f4` (main, 2026-11-21).
- APatch commit `e8e4651c16fb5075882a25813c8732285fdb3505` (main, 2026-10-12).

## Kernel behaviour

| claim | source | level |
|---|---|---|
| `struct module` carries `state`, `list`, `name[]`; `init` and `exit` are function pointers whose offsets depend on the build | `include/linux/module.h:411` (`struct module`), `:412`, `:415`, `:418`, `:470` (`init`), `:584` (`exit`) | A |
| `MODULE_ARCH_INIT` is `{}` unless the architecture overrides it; arm64 does not override it | `include/linux/module.h:614`; `arch/arm64/include/asm/module.h` defines only `struct mod_arch_specific`, no `MODULE_ARCH_INIT` | A |
| modpost emits `.gnu.linkonce.this_module` with `.name`, `.init`, `.exit` (exit only with `CONFIG_MODULE_UNLOAD`) | `scripts/mod/modpost.c:1793-1802` | A |
| the kernel refuses a `.this_module` whose `sh_size != sizeof(struct module)` | `kernel/module/main.c:2046-2050` | A |
| the kernel reads the module name at the kernel's own `name` offset from the section, not at the module's | `kernel/module/main.c:2328` (`info->mod = hdr + sh_offset`), `:2335` (`info->name = info->mod->name`) | A |
| a mismatch is logged as `version magic '<module>' should be '<kernel>'` | `kernel/module/main.c:2536-2538` | A |
| `SHT_NOBITS` sections have no file contents and are skipped when validating section bounds | `kernel/module/main.c:1878-1882` (`case SHT_NOBITS: /* No contents, offset/size don't mean anything */ continue;`) | A |
| `.this_module` relocations are applied to the copied section during load | `kernel/module/main.c:1554` (`apply_relocations`), relocation loop from `:1560` | A |
| the module link order puts the main object first and the modpost object last, and `.bss` is a named output section while `.gnu.linkonce.this_module` is an orphan placed after the named sections | `scripts/Makefile.modfinal:67` (`%.ko: %.o %.mod.o ...`), `scripts/module.lds.S:74-77` (`.bss`), `scripts/module.lds.S:92` (`.text`), `:107` (arch sections) | A |

Consequence: a module built against different headers can be accepted by the
kernel only if its `.this_module` section is exactly the running kernel's
`sizeof(struct module)`; and if it is accepted, the kernel reads `name` at its
own offset.  Adapting the section therefore has to rewrite `sh_offset`/
`sh_size`, place the name at the kernel's `name` offset and move the
`init_module`/`cleanup_module` relocations to the kernel's `init`/`exit`
offsets.  That is what `lkm_adapt_module_layout()` does.

## Host measurement (B)

`/sys/kernel/btf/vmlinux` exists on the development host; parsing it with the
same code the binary uses produced:

```
$ ls -l /sys/kernel/btf/vmlinux
-r--r--r--. 1 root root 6888351 ... /sys/kernel/btf/vmlinux
$ ./btfprobe            # links src/lkm_insmod.c
rc=0 size=1600 name_off=24 init_off=392 have_exit=1 exit_off=1528
```

`name_off=24` is the layout the headers imply: `state` (4 bytes) plus 4 bytes
of padding plus `list_head` (16 bytes).  This is a real GKI BTF blob, not a
fixture.

## `SHT_NOBITS` regression (C)

Before the fix, a legal `.bss` (type `SHT_NOBITS`, `sh_offset=2000`,
`sh_size=1 MiB`) placed before `.gnu.linkonce.this_module` made the patcher
report `section 1 outside the image` and return `ENOEXEC`; the kernel itself
skips that section (`kernel/module/main.c:1878-1882`).  The regression test is
`tests/host/lkm_insmod_test.c` (`test_abi_nobits()`), which builds exactly that
image.  With the skip removed from a copy of `src/lkm_insmod.c`, the test
fails with the message above; with the fix it passes.

## Reference implementations

| claim | source | level |
|---|---|---|
| ksuinit opens `/dev/kmsg` (or `/kmsg`) non-blocking, positions at the end before the first load | KernelSU `userspace/ksuinit/src/lib.rs:88-116` | A |
| it reads only records written after that point, one read per record | KernelSU `lib.rs:118-135` | A |
| it takes the newest `version magic '...' should be '...'` record | KernelSU `lib.rs:137-166` (`PREFIX`, `SEPARATOR`, `lines().rev()`) | A |
| it rewrites the module's `.modinfo` vermagic | KernelSU `lib.rs:203` (`replace_module_vermagic`) | A |
| it retries `init_module(2)` exactly once | KernelSU `lib.rs:422-445` | A |
| `ksud insmod` canonicalizes the module path and prints `Loaded kernel module: <path>` | KernelSU `userspace/ksud/src/debug.rs:54-81`; dispatch at `cli.rs:539` | A |
| `apd insmod` canonicalizes and prints the same line | APatch `apd/src/insmod.rs:123`, `:130` | A |

## Not verified in this change set (D)

These are stated as unverified rather than silently treated as fact:

- The README's `[permanent]` episode (`exit` read as NULL after a layout
  mismatch) is a report from a device session; there is no log artifact in
  this repository yet.
- The pre-existing README claim that a 678-symbol module binds with zero
  unresolved symbols has no captured output either.
- No adapted `.ko` has been loaded end to end here: this change set verifies
  the ELF/section rewriting (B and C) but not a successful `init_module(2)` on
  a kernel whose `struct module` layout differs.  The next gate is a QEMU or
  device run; until then the README's "does not require a per-kernel module
  build" is the design goal, not a measured result.

## Run record

| run id | when (UTC) | commit / tree | command | result |
|---|---|---|---|---|
| `local-2026-11-21T10:52Z` | 2026-11-21T10:52Z | host kernel `6.12.30-android16-5` | BTF probe linked against `src/lkm_insmod.c` | `size=1600 name_off=24 init_off=392 exit_off=1528` |
| `local-2026-11-21T11:04Z` | 2026-11-21T11:04Z | clean clone of `origin/master` = `b6f7e0a` | `make test` | 29 + 163 + 12 checks, 0 failures, exit 0 |
| `local-2026-11-21T13:24Z` | 2026-11-21T13:24Z | working tree at `b6f7e0a` | `make test` | 29 + 163 + 12 checks, 0 failures, exit 0 |

GitHub Actions usage: 0/9.  No workflow run was ever dispatched: there is no
workflow in the repository (`ls .github/workflows` -> ENOENT), `gh run list -R
uobe1/droid-lkm-ins` returns no runs, and every entry above is a foreground
local run.  The "A1/A2/A3" batches in the session notes are local verification
batches, not CI dispatches.  Adding a workflow is a separate change set.

## Android static target (B)

The host has NDK headers at `/usr/local/share/ndk` but no bionic sysroot and no
Android clang driver (only `include/`, `sources/` and an include-only
`sysroot/`), and installing a toolchain is out of scope for this repository.
The `android` target therefore uses the existing aarch64 glibc cross toolchain:

```
$ aarch64-linux-gnu-gcc --version | head -1
aarch64-linux-gnu-gcc (Debian 16.2.0-4) 16.2.0
$ make android
$ file build/lkmctl-android
build/lkmctl-android: ELF 64-bit LSB executable, ARM aarch64, version 1
(GNU/Linux), statically linked, BuildID[sha1]=<id>, for GNU/Linux 3.7.0,
not stripped
$ readelf -l build/lkmctl-android | grep INTERP   # no output, exit 1
$ readelf -d build/lkmctl-android
There is no dynamic section in this file.
$ ./build/lkmctl-android          # host is aarch64; prints usage, exit 2
```

This is **not** a bionic build: it is a static glibc ELF with no `PT_INTERP`,
so it does not need `/system/bin/linker64` or `/lib/ld-linux-aarch64.so.1`.
Executing it on the Android device is the droid-hook gate's claim; it is not
verified here.

## Run record (Android)

| run id | when (UTC) | commit / tree | command | result |
|---|---|---|---|---|
| `local-2026-11-21T13:57Z` | 2026-11-21T13:57Z | working tree at `40034c7` + android target | `make android`; `file`; `readelf -h/-l/-d`; host run | aarch64 static ELF, no `INTERP`, no dynamic section, host run exit 2 (usage) |

## Cancelled direction: cross-KMI (closed 2026-11-22)

Cross-KMI loading was never a project requirement.  The one attempt at it is
recorded here so it is not repeated:

- Artifact: `kmi61_probe.ko`, built by workflow `build-kmi61-module` from the
  `android14-6.1` DDK (clang 17.0.2), sha256
  `d58d39c75d32c5dc8ad120146f6c40fdf7f4ed13405f5486b7ee048d216d063b`,
  run `44976400067`, headSha `7e6e4585`.
- Its real cross-KMI values: `.gnu.linkonce.this_module` = `0x440` (1088
  bytes), `init`/`exit` relocations at 368/984, vermagic
  `6.1.166-dirty SMP preempt mod_unload modversions aarch64`.
- The device (`6.12.30-android16-5`, layout 1600/24/392/1528, vermagic
  `...-android16-5`) reached `do_init_module`, i.e. the vermagic rewrite and
  the section-layout adaptation were both accepted, then died in
  `do_one_initcall`:

```
kmi61_probe: no symbol version for module_layout
Failed to load code tags of type alloc_tags from the module kmi61_probe
CFI failure at do_one_initcall+0xd4/0x34c (target: init_module+0x0/0xfe4 [kmi61_probe]; expected type: 0x6fbb3035)
Internal error: Oops - CFI: 00000000f2008233 [#1] PREEMPT SMP
```

- Cause: the device runs `CONFIG_CFI_CLANG=y` with `CONFIG_CFI_PERMISSIVE`
  unset (verified from `/proc/config.gz`), and the 6.1 build carries no
  `__cfi_*` / `.kcfi_traps` (`nm`/`readelf`: 0 matches).  KCFI compares type
  hashes at the indirect call and cannot be repaired from user space, so a
  cross-KMI module is structurally unloadable-on-load on this device.
- Consequence: the probe files, workflow and commit were removed from this
  repository.  The device rebooted on its own after the panic
  (`ro.boot.bootreason=kernel_panic`); `kmi61_probe` left no residue
  (`/proc/modules` match count 0).
- Scope now stated in the README: same KMI (`android16-6.12`) only.

## Same-KMI gate (planned, not yet run)

The verification that remains is same-KMI + a reproducible synthetic layout
delta: take a real `android16-6.12` module whose `.this_module` already
matches, move `sh_size` and the `init`/`exit` relocations to a second known
set, and let `lkmctl` adapt them back — in QEMU first, on a device only after
that gate is green.  No Action has been dispatched for it.

## Same-KMI QEMU gate: run record

Gate: `.github/workflows/qemu-insmod.yml` (jobs `image`, `gate`).  It builds
the `android16-6.12` Image and `ci/samekmi/samekmi_probe.ko` from the same DDK
tree, moves the module's `.this_module` layout to `1584 / 376 / 1512` with
`scripts/synthetic-layout-delta.py`, then boots QEMU and requires
`LKM_QEMU_{BOOT,LOAD,MODULE_VISIBLE,RMMOD,NO_RESIDUE,OK}` with no
`CFI failure|Oops|BUG:|Kernel panic|invalid module format|Unknown symbol`.

Local dry-run of the delta and its adaptation (before any dispatch):

```
fixture: this_module 1600 -> 1584, init 392 -> 376, exit 1528 -> 1512
target layout: size=1600 name=24 init=392 exit=1528
adapt rc=0 detaillen=4016  -> this_module 0x640, init 0x188, exit 0x5f8
```

| run id | when (UTC) | headSha | result |
|---|---|---|---|
| `44978026251` | 2026-11-22T02:51Z | `7fab4ba` | **failed** before boot: `apt-get` needs `sudo` on the runner (`Permission denied` on `/var/lib/apt/lists/lock`) |
| `44978217732` | 2026-11-22T02:56Z | `88c442a` | **failed** before boot: `qemu-system-aarch64: failed to find romfile "efi-virtio.rom"`; `qemu.log` is that one line |

Neither run reached `LKM_QEMU_BOOT_OK`, so **no conclusion is drawn about the
adaptation from CI yet**.  Fix applied but not re-dispatched (the one allowed
retry was already spent): install `ipxe-qemu` and boot with `-nic none`, so no
option ROM is requested.
