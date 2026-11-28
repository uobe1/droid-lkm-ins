/* SPDX-License-Identifier: GPL-2.0-only
 *
 * lkm_bind.h - bind a .ko's undefined symbols, then let the kernel load it.
 *
 * DESIGN NOTE (why this is not a module loader)
 *
 * The obvious idea -- copy the .ko into kernel memory, apply the relocations
 * ourselves, run module_init -- is what this project first tried and it is the
 * wrong shape.  KernelSU (`kernel/preinit/runner/runner.c`) and APatch
 * (`apd/src/insmod.rs`, an explicit port of KernelSU's ksuinit) both do
 * something much smaller:
 *
 *   1. walk the ELF symtab;
 *   2. for every SHN_UNDEF symbol, look the address up and rewrite the symbol
 *      entry in place to  st_value = <address>, st_shndx = SHN_ABS;
 *   3. hand the patched image to the kernel's own init_module(2).
 *
 * The kernel then does the real work: allocation of executable module memory,
 * relocation, CONFIG_STRICT_MODULE_RWX, lifecycle, /sys/module, refcounting and
 * removal.  Re-implementing that inside a module is how you end up with the
 * exact failure modes this project already fought: pinned modules, hooks that
 * outlive their text, and a refcount that never drains.
 *
 * So this header binds symbols and nothing else.  Everything below the bind is
 * the kernel's job, and it stays the kernel's job.
 *
 * What the bind has to get right, learned from both references:
 *   - kptr_restrict must be relaxed while reading addresses (otherwise
 *     /proc/kallsyms reports all zeros and every symbol looks missing);
 *   - /proc/kallsyms lists kernel symbols first and module symbols after; stop
 *     at the first module entry so a module's symbol never shadows a kernel one;
 *   - compiler-generated suffixes (`foo$...`, `foo.llvm.NNN`, `.cfi_jt`
 *     variants) must be folded back to the plain name;
 *   - a symbol that cannot be resolved is reported, not silently left for the
 *     kernel to reject with an unhelpful "Unknown symbol" later.
 */
#ifndef LKM_BIND_H
#define LKM_BIND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LKM_BIND_ABI_VERSION 1u

#if defined(LKM_BIND_SHARED) && defined(__GNUC__)
#define LKM_BIND_API __attribute__((visibility("default")))
#else
#define LKM_BIND_API
#endif

#define LKM_BIND_OK 0
#define LKM_BIND_EINVAL (-22)
#define LKM_BIND_ENOEXEC (-8)
#define LKM_BIND_ENOENT (-2)
#define LKM_BIND_ENOMEM (-12)
#define LKM_BIND_E2BIG (-7)
#define LKM_BIND_EIO (-5)

/* A kallsyms provider.  `lookup` returns 0 when the symbol is unknown. */
struct lkm_symtab {
	void *ctx;
	uint64_t (*lookup)(void *ctx, const char *name);
	/*
	 * Optional: called once per symbol that could not be bound, so the caller
	 * can log it.  Returning non-zero aborts the bind with that error.
	 */
	int (*on_unresolved)(void *ctx, const char *name);
};

struct lkm_bind_stats {
	uint32_t undefined;   /* SHN_UNDEF symbols found */
	uint32_t bound;       /* rewritten to SHN_ABS */
	uint32_t unresolved;  /* left undefined */
	uint32_t relocated;   /* RELA entries whose target symbol was bound */
};

/*
 * Bind every undefined symbol in the ELF64 relocatable object `data` in place.
 *
 * The buffer is modified, so pass something you own (APatch and KernelSU both
 * read the .ko into a mutable copy first).  `stats` and `diag` may be NULL.
 *
 * On LKM_BIND_OK the caller may hand `data`/`size` to init_module(2).  On any
 * other return the buffer must be discarded: a partially bound image would be
 * rejected by the kernel with a misleading error.
 */
LKM_BIND_API int lkm_bind_symbols(void *data, size_t size,
				  const struct lkm_symtab *symtab,
				  struct lkm_bind_stats *stats,
				  char *diag, size_t diag_len);

/*
 * Normalize a kallsyms name so lookup succeeds for the plain symbol name:
 * strips "$...", ".llvm.NNN" and a trailing ".cfi_jt".
 *
 * Returns `name` when no suffix applies, otherwise writes the trimmed name into
 * `buf` and returns that.  Kept public because the caller usually needs the same
 * rule when it builds its own symbol table.
 */
LKM_BIND_API const char *lkm_strip_symbol_suffix(const char *name,
						 char *buf, size_t buf_len);

LKM_BIND_API uint32_t lkm_bind_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* LKM_BIND_H */

/* ====================================================================== */
#ifdef LKM_BIND_IMPLEMENTATION
#ifndef LKM_BIND_IMPL_ONCE
#define LKM_BIND_IMPL_ONCE

#include <string.h>

/* ELF64, defined locally so the header needs no <elf.h> on either side. */
#define LKM_ELFCLASS64 2
#define LKM_ELFDATA2LSB 1
#define LKM_ET_REL 1
#define LKM_SHT_SYMTAB 2
#define LKM_SHT_RELA 4
#define LKM_SHT_STRTAB 3
#define LKM_SHN_UNDEF 0
#define LKM_SHN_ABS 0xfff1
#define LKM_EM_AARCH64 183

struct lkm_elf_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
};

struct lkm_elf_sym {
	uint32_t st_name;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t st_shndx;
	uint64_t st_value;
	uint64_t st_size;
};

struct lkm_elf_rela {
	uint64_t r_offset;
	uint64_t r_info;
	int64_t r_addend;
};

struct lkm_elf_ehdr {
	unsigned char e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

static void lkm_bind_set_diag(char *diag, size_t len, const char *msg)
{
	size_t n;

	if (!diag || !len)
		return;
	n = strlen(msg);
	if (n >= len)
		n = len - 1;
	memcpy(diag, msg, n);
	diag[n] = '\0';
}

/* Every range check goes through here: a malformed .ko must never make us read
 * outside the caller's buffer. */
static int lkm_bind_range(uint64_t off, uint64_t size, size_t total)
{
	if (off > total)
		return 0;
	if (size > total - off)
		return 0;
	return 1;
}

LKM_BIND_API const char *lkm_strip_symbol_suffix(const char *name,
						 char *buf, size_t buf_len)
{
	size_t i, n;

	if (!name || !name[0])
		return name;
	n = strlen(name);
	/* A trailing .cfi_jt is a KCFI jump table thunk, not a different symbol. */
	if (n > 7 && !strcmp(name + n - 7, ".cfi_jt")) {
		n -= 7;
	} else {
		/* "$..." suffixes are local variants; ".llvm.NNN" are compiler clones.
		 * Keep the C-level name in both cases. */
		for (i = 0; i < n; i++) {
			if (name[i] == '$') {
				n = i;
				break;
			}
			if (name[i] == '.' && i + 6 < n && !strncmp(name + i, ".llvm.", 6)) {
				n = i;
				break;
			}
		}
	}
	if (n == strlen(name))
		return name;
	if (!buf || buf_len <= n)
		return name;
	memcpy(buf, name, n);
	buf[n] = '\0';
	return buf;
}

LKM_BIND_API int lkm_bind_symbols(void *data, size_t size,
				  const struct lkm_symtab *symtab,
				  struct lkm_bind_stats *stats,
				  char *diag, size_t diag_len)
{
	struct lkm_elf_ehdr *eh;
	struct lkm_elf_shdr *shdrs;
	struct lkm_elf_shdr *symsec = NULL, *strsec;
	struct lkm_elf_sym *syms;
	const char *strtab;
	uint64_t nsyms, strsz, i;
	uint32_t bound = 0, unresolved = 0, undefined = 0;
	int ret = LKM_BIND_OK;

	if (stats)
		memset(stats, 0, sizeof(*stats));
	if (!data || size < sizeof(struct lkm_elf_ehdr)) {
		lkm_bind_set_diag(diag, diag_len, "buffer too small for an ELF header");
		return LKM_BIND_ENOEXEC;
	}
	if (!symtab || !symtab->lookup) {
		lkm_bind_set_diag(diag, diag_len, "no symbol provider");
		return LKM_BIND_EINVAL;
	}

	eh = (struct lkm_elf_ehdr *)data;
	if (memcmp(eh->e_ident, "\177ELF", 4) || eh->e_ident[4] != LKM_ELFCLASS64 ||
	    eh->e_ident[5] != LKM_ELFDATA2LSB || eh->e_type != LKM_ET_REL) {
		lkm_bind_set_diag(diag, diag_len,
				  "not a little-endian ELF64 relocatable object");
		return LKM_BIND_ENOEXEC;
	}
	if (eh->e_machine != LKM_EM_AARCH64) {
		lkm_bind_set_diag(diag, diag_len, "not an aarch64 object");
		return LKM_BIND_ENOEXEC;
	}
	if (!eh->e_shentsize || eh->e_shentsize != sizeof(struct lkm_elf_shdr) ||
	    !lkm_bind_range(eh->e_shoff, (uint64_t)eh->e_shnum * eh->e_shentsize, size)) {
		lkm_bind_set_diag(diag, diag_len, "bad section header table");
		return LKM_BIND_ENOEXEC;
	}

	shdrs = (struct lkm_elf_shdr *)((char *)data + eh->e_shoff);
	for (i = 0; i < eh->e_shnum; i++) {
		if (shdrs[i].sh_type == LKM_SHT_SYMTAB) {
			symsec = &shdrs[i];
			break;
		}
	}
	if (!symsec) {
		lkm_bind_set_diag(diag, diag_len, "no symtab section");
		return LKM_BIND_ENOEXEC;
	}
	if (!symsec->sh_entsize || symsec->sh_entsize != sizeof(struct lkm_elf_sym) ||
	    symsec->sh_size % sizeof(struct lkm_elf_sym) ||
	    !lkm_bind_range(symsec->sh_offset, symsec->sh_size, size) ||
	    symsec->sh_link >= eh->e_shnum) {
		lkm_bind_set_diag(diag, diag_len, "bad symtab section");
		return LKM_BIND_ENOEXEC;
	}

	strsec = &shdrs[symsec->sh_link];
	if (strsec->sh_type != LKM_SHT_STRTAB || !strsec->sh_size ||
	    !lkm_bind_range(strsec->sh_offset, strsec->sh_size, size)) {
		lkm_bind_set_diag(diag, diag_len, "bad symbol string table");
		return LKM_BIND_ENOEXEC;
	}
	strtab = (const char *)data + strsec->sh_offset;
	strsz = strsec->sh_size;
	/* A missing trailing NUL means some name runs past the table. */
	if (strtab[strsz - 1] != '\0') {
		lkm_bind_set_diag(diag, diag_len, "symbol table is not NUL-terminated");
		return LKM_BIND_ENOEXEC;
	}

	syms = (struct lkm_elf_sym *)((char *)data + symsec->sh_offset);
	nsyms = symsec->sh_size / sizeof(struct lkm_elf_sym);

	/* Entry 0 is the reserved null symbol and must stay untouched. */
	for (i = 1; i < nsyms; i++) {
		struct lkm_elf_sym *sym = &syms[i];
		const char *raw;
		const char *name;
		char trimmed[256];
		uint64_t addr;

		if (sym->st_shndx != LKM_SHN_UNDEF)
			continue;
		if (sym->st_name >= strsz || !strtab[sym->st_name])
			continue;
		undefined++;
		raw = strtab + sym->st_name;
		name = lkm_strip_symbol_suffix(raw, trimmed, sizeof(trimmed));
		addr = symtab->lookup(symtab->ctx, name);
		if (!addr && name != raw)
			addr = symtab->lookup(symtab->ctx, raw);

		if (!addr) {
			unresolved++;
			if (symtab->on_unresolved) {
				ret = symtab->on_unresolved(symtab->ctx, name);
				if (ret)
					goto out;
			}
			continue;
		}

		/*
		 * This is the whole trick: present the symbol as an absolute
		 * definition at the address the kernel already uses.  The kernel's
		 * own relocation then treats it like any other resolved symbol, so it
		 * never reports "Unknown symbol" and never applies a modversions CRC
		 * to something that was not a real export.
		 */
		sym->st_value = addr;
		sym->st_shndx = LKM_SHN_ABS;
		bound++;
	}

out:
	if (stats) {
		stats->undefined = undefined;
		stats->bound = bound;
		stats->unresolved = unresolved;
	}
	if (ret)
		return ret;
	/*
	 * Unresolved symbols are NOT a hard failure, and both references agree:
	 * they leave the symbol undefined and let init_module resolve it the
	 * normal (exported) way.  Failing here would reject images the kernel
	 * would have loaded happily, and it would hide which symbol was missing
	 * behind a generic error.  The count is reported so the caller can warn.
	 */
	if (stats)
		stats->unresolved = unresolved;
	if (unresolved)
		lkm_bind_set_diag(diag, diag_len,
				  "some symbols were left for the kernel to resolve");
	return LKM_BIND_OK;
}

LKM_BIND_API uint32_t lkm_bind_abi_version(void)
{
	return LKM_BIND_ABI_VERSION;
}

#endif /* LKM_BIND_IMPL_ONCE */
#endif /* LKM_BIND_IMPLEMENTATION */
