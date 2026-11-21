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
