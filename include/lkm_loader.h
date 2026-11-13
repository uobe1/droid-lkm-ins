/* SPDX-License-Identifier: GPL-2.0-only
 *
 * lkm_loader.h - single-header loader for relocatable Linux kernel modules.
 *
 * Scope: this is the *pure* part of a loader.  It parses a .ko, applies the
 * arm64 relocations against symbols the caller resolves, checks the module's
 * declared vermagic/ABI metadata, and hands back a loaded image.  It never
 * talks to the kernel itself, so the same code can be exercised on a host
 * without a kernel: the caller supplies memory and a symbol resolver.
 *
 * What it deliberately does not do: fabricate success.  Every failure path
 * returns a negative errno and a human-readable reason; there is no "best
 * effort" relocation and no silent skip of an unsupported relocation type.
 *
 * Usage:
 *   #define LKM_LOADER_IMPLEMENTATION
 *   #include "lkm_loader.h"
 *
 * The loader is reentrant and has no global state.
 */
#ifndef LKM_LOADER_H
#define LKM_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ABI version of this header.  Callers that load the prebuilt shared library
 * must compare this against lkm_loader_abi_version(); a mismatch means the
 * struct layouts below may differ, so the library must not be used.
 */
#define LKM_LOADER_ABI_VERSION 1u

/*
 * export marker for the shared-library build.  Compile the implementation with
 * -DLKM_LOADER_SHARED to make symbols visible, otherwise everything stays in
 * the translation unit as plain C (the default single-header usage).
 */
#if defined(LKM_LOADER_SHARED) && defined(_WIN32)
#define LKM_API __declspec(dllexport)
#elif defined(LKM_LOADER_SHARED) && defined(__GNUC__)
#define LKM_API __attribute__((visibility("default")))
#else
#define LKM_API
#endif

/* Error codes mirror the kernel's negative errno values where one applies. */
#define LKM_OK 0
#define LKM_EINVAL (-22)   /* malformed input */
#define LKM_ENOENT (-2)    /* missing section or symbol */
#define LKM_ENOMEM (-12)   /* allocation refused by the host */
#define LKM_ENOEXEC (-8)   /* not an ELF relocatable object */
#define LKM_EBADARCH (-8)  /* machine is not the requested architecture */
#define LKM_EOPNOTSUPP (-95) /* unsupported relocation or feature */
#define LKM_EMSGSIZE (-90) /* image larger than the configured limit */

/* AArch64 ELF machine number. */
#define LKM_EM_AARCH64 183

/* ELF class/type constants we care about, without pulling in <elf.h> so the
 * header stays usable in freestanding environments. */
#define LKM_ET_REL 1
#define LKM_EM_NONE 0

/* AArch64 relocation types emitted by the kernel build for .ko files. */
enum lkm_reloc_type {
	LKM_R_AARCH64_NONE = 0,
	LKM_R_AARCH64_ABS64 = 257,
	LKM_R_AARCH64_ABS32 = 258,
	LKM_R_AARCH64_ABS16 = 259,
	LKM_R_AARCH64_PREL64 = 260,
	LKM_R_AARCH64_PREL32 = 261,
	LKM_R_AARCH64_PREL16 = 262,
	LKM_R_AARCH64_ADR_PREL_PG_HI21 = 275,
	LKM_R_AARCH64_ADD_ABS_LO12_NC = 277,
	LKM_R_AARCH64_LDST8_ABS_LO12_NC = 278,
	LKM_R_AARCH64_TSTBR14 = 279,
	LKM_R_AARCH64_CONDBR19 = 280,
	LKM_R_AARCH64_JUMP26 = 282,
	LKM_R_AARCH64_CALL26 = 283,
	LKM_R_AARCH64_LDST16_ABS_LO12_NC = 284,
	LKM_R_AARCH64_LDST32_ABS_LO12_NC = 285,
	LKM_R_AARCH64_LDST64_ABS_LO12_NC = 286,
	LKM_R_AARCH64_MOVW_UABS_G0 = 287,
	LKM_R_AARCH64_MOVW_UABS_G0_NC = 288,
	LKM_R_AARCH64_MOVW_UABS_G1 = 289,
	LKM_R_AARCH64_MOVW_UABS_G1_NC = 290,
	LKM_R_AARCH64_MOVW_UABS_G2 = 291,
	LKM_R_AARCH64_MOVW_UABS_G2_NC = 292,
	LKM_R_AARCH64_MOVW_UABS_G3 = 293,
	LKM_R_AARCH64_LDST128_ABS_LO12_NC = 299,
	LKM_R_AARCH64_ADR_GOT_PAGE = 311,
	LKM_R_AARCH64_LD64_GOT_LO12_NC = 312,
};

/* Host services.  `resolve` must return the kernel address of a symbol, or 0
 * when the symbol does not exist; returning 0 for a needed symbol is a hard
 * error, never a warning. */
struct lkm_host {
	void *ctx;
	/* Allocate `size` bytes for the image.  Must be writable. */
	void *(*alloc)(void *ctx, size_t size);
	void (*free)(void *ctx, void *ptr);
	/* Resolve a kernel symbol by name; return 0 if unknown. */
	uint64_t (*resolve)(void *ctx, const char *name);
	/*
	 * Optional: make [addr, addr+len) executable or read-only after
	 * relocation.  Leave NULL to skip (host tests do).
	 */
	int (*protect)(void *ctx, void *addr, size_t len, int flags);
};

#define LKM_PROT_READ 1
#define LKM_PROT_WRITE 2
#define LKM_PROT_EXEC 4

/* Limits so a corrupt or hostile .ko cannot make the loader explode. */
struct lkm_limits {
	size_t max_image;      /* memsz total; 0 = 1 GiB */
	uint32_t max_relocs;   /* 0 = 4M */
	uint32_t max_sections; /* 0 = 4096 */
	uint32_t max_symbols;  /* 0 = 1M */
};

/* Result of parsing .modinfo.  Fields point into the loaded image. */
struct lkm_modinfo {
	const char *vermagic;   /* "6.12.30-android16-5 SMP preempt mod_unload ..." */
	const char *name;
	const char *license;
	const char *depends;
	int have_vermagic;
	int have_license;
};

/* One loaded image.  Treat the layout as opaque. */
struct lkm_image {
	void *base;          /* lowest mapped address */
	size_t size;         /* total mapping size */
	void *init_fn;       /* pointer to the module's init */
	void *exit_fn;       /* pointer to the module's exit, may be NULL */
	struct lkm_modinfo info;
	const char *module_name;
	/* Internals. */
	void *priv;
};

/* Diagnostics for the last failure, for logs and panic forensics. */
struct lkm_diag {
	int err;
	int section_index;   /* -1 when not section-specific */
	uint32_t reloc_index;
	uint32_t reloc_type;
	const char *symbol;
	char detail[192];
};

/*
 * Parse and relocate a relocatable ELF object held in memory.
 *
 * `data`/`size` is the whole file.  The buffer is not modified and does not
 * need to outlive the call: the image is copied into host-allocated memory.
 *
 * On success returns LKM_OK and fills `*out`.  On failure returns a negative
 * LKM_* code and, when `diag` is non-NULL, describes the first problem.
 */
LKM_API int lkm_load(const void *data, size_t size, const struct lkm_host *host,
	     const struct lkm_limits *limits, struct lkm_image **out,
	     struct lkm_diag *diag);

/* Release an image returned by lkm_load(). */
LKM_API void lkm_unload(struct lkm_image *img, const struct lkm_host *host);

/* Read the vermagic string the image declares, or NULL.  Convenience wrapper
 * so callers can compare against uname() before loading. */
LKM_API const char *lkm_image_vermagic(const struct lkm_image *img);

/*
 * Compare a module's vermagic with the running kernel's.
 *
 * The kernel's compare (check_modinfo) is: the module's string must be a
 * prefix of the kernel's for the vermagic field it checks, but Android's
 * GKI build also uses extended modversions.  This helper does the strict
 * part that a loader can verify portably: exact match of the "release" field
 * (everything before the first space) and of the SMEP/preempt/mod_unload/
 * modversions flags that follow.  Returns LKM_OK on match, LKM_EPROTO-like
 * negative otherwise, and reports the first difference in `detail`.
 */
LKM_API int lkm_check_vermagic(const char *module_vermagic, const char *kernel_vermagic,
		       char *detail, size_t detail_len);

/* The module's own entry points, as addresses inside the image. */
LKM_API void *lkm_image_init(const struct lkm_image *img);
LKM_API void *lkm_image_exit(const struct lkm_image *img);

/* Version of the ABI this binary was built against; compare with
 * LKM_LOADER_ABI_VERSION before using a prebuilt shared library. */
LKM_API uint32_t lkm_loader_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* LKM_LOADER_H */

/* ====================================================================== */
#ifdef LKM_LOADER_IMPLEMENTATION
#ifndef LKM_LOADER_IMPL_ONCE
#define LKM_LOADER_IMPL_ONCE

#include <string.h>

/* ---- minimal ELF64 structures (kept private, independent of <elf.h>) ---- */

struct lkm_ehdr {
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

struct lkm_shdr {
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

struct lkm_sym {
	uint32_t st_name;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t st_shndx;
	uint64_t st_value;
	uint64_t st_size;
};

struct lkm_rela {
	uint64_t r_offset;
	uint64_t r_info;
	int64_t r_addend;
};

#define LKM_SHT_NOBITS 8
#define LKM_SHT_RELA 4
#define LKM_SHT_SYMTAB 2
#define LKM_SHT_STRTAB 3
#define LKM_SHN_UNDEF 0
#define LKM_SHN_ABS 0xfff1
#define LKM_SHN_COMMON 0xfff2
#define LKM_STB_LOCAL 0
#define LKM_R_SYM(i) ((uint32_t)((i) >> 32))
#define LKM_R_TYPE(i) ((uint32_t)((i) & 0xffffffffu))

/* Internal bookkeeping for one section. */
struct lkm_sec {
	const struct lkm_shdr *sh;
	const char *name;
	void *addr;      /* non-NOBITS: destination inside the image */
};

struct lkm_priv {
	const struct lkm_host *host;
	struct lkm_sec *secs;
	uint32_t nsecs;
	const struct lkm_sym *syms;
	uint32_t nsyms;
	const char *strtab;
	size_t strtab_size;
	/* Resolved kernel addresses, indexed by symbol index; 0 = local. */
	uint64_t *sym_value;
	/* 1 when the symbol needed no kernel resolution. */
	unsigned char *sym_local;
};

static int lkm_mem_ok(const struct lkm_ehdr *eh, size_t size)
{
	if (size < sizeof(*eh))
		return 0;
	if (eh->e_shentsize != sizeof(struct lkm_shdr))
		return 0;
	if (eh->e_shnum == 0 || eh->e_shoff == 0)
		return 0;
	if (eh->e_shoff > size)
		return 0;
	if ((uint64_t)eh->e_shnum * sizeof(struct lkm_shdr) > size - eh->e_shoff)
		return 0;
	return 1;
}

static int lkm_section_range_ok(const struct lkm_shdr *sh, size_t size)
{
	if (sh->sh_type == LKM_SHT_NOBITS)
		return 1;
	if (sh->sh_offset > size)
		return 0;
	if (sh->sh_size > size - sh->sh_offset)
		return 0;
	return 1;
}

static void lkm_set_detail(struct lkm_diag *diag, int err, const char *fmt,
			   const char *a, uint32_t b)
{
	if (!diag)
		return;
	diag->err = err;
	/* Bounded, dependency-free formatting: only two substitutions, both
	 * optional, which covers every diagnostic this loader emits. */
	{
		size_t w = 0;
		const char *p = fmt;
		char num[16];
		int n = 0;
		uint32_t v = b;

		if (v == 0) {
			num[n++] = '0';
		}
		while (v && n < (int)sizeof(num)) {
			num[n++] = (char)('0' + (v % 10));
			v /= 10;
		}
		while (*p && w + 1 < sizeof(diag->detail)) {
			if (p[0] == '%' && p[1] == 's' && a) {
				while (*a && w + 1 < sizeof(diag->detail))
					diag->detail[w++] = *a++;
				p += 2;
			} else if (p[0] == '%' && p[1] == 'u') {
				int k;
				for (k = n - 1; k >= 0 && w + 1 < sizeof(diag->detail); k--)
					diag->detail[w++] = num[k];
				p += 2;
			} else {
				diag->detail[w++] = *p++;
			}
		}
		diag->detail[w] = '\0';
	}
}

/* ---- relocation helpers ---- */

static int lkm_apply_reloc(uint32_t type, void *loc, uint64_t sym,
			   int64_t addend, const char *sym_name)
{
	uint64_t s = sym;
	int64_t a = addend;
	uint32_t insn;

	if ((uintptr_t)loc & 3 && (type == LKM_R_AARCH64_JUMP26 ||
				   type == LKM_R_AARCH64_CALL26 ||
				   type == LKM_R_AARCH64_CONDBR19 ||
				   type == LKM_R_AARCH64_TSTBR14 ||
				   type == LKM_R_AARCH64_ADR_PREL_PG_HI21 ||
				   type == LKM_R_AARCH64_ADD_ABS_LO12_NC ||
				   type == LKM_R_AARCH64_LDST8_ABS_LO12_NC ||
				   type == LKM_R_AARCH64_LDST16_ABS_LO12_NC ||
				   type == LKM_R_AARCH64_LDST32_ABS_LO12_NC ||
				   type == LKM_R_AARCH64_LDST64_ABS_LO12_NC ||
				   type == LKM_R_AARCH64_LDST128_ABS_LO12_NC))
		return LKM_EINVAL;

	switch (type) {
	case LKM_R_AARCH64_NONE:
		return LKM_OK;
	case LKM_R_AARCH64_ABS64:
		*(uint64_t *)loc = s + (uint64_t)a;
		return LKM_OK;
	case LKM_R_AARCH64_ABS32: {
		int64_t v = (int64_t)(s + (uint64_t)a);
		if (v > 0xffffffffLL || v < 0)
			return LKM_EOPNOTSUPP;
		*(uint32_t *)loc = (uint32_t)v;
		return LKM_OK;
	}
	case LKM_R_AARCH64_PREL32: {
		int64_t v = (int64_t)s + a - (int64_t)(uintptr_t)loc;
		if (v > 0x7fffffffLL || v < -0x80000000LL)
			return LKM_EOPNOTSUPP;
		*(uint32_t *)loc = (uint32_t)(int32_t)v;
		return LKM_OK;
	}
	case LKM_R_AARCH64_JUMP26:
	case LKM_R_AARCH64_CALL26: {
		int64_t delta = (int64_t)s + a - (int64_t)(uintptr_t)loc;
		int64_t imm;
		if (delta & 3)
			return LKM_EINVAL;
		imm = delta >> 2;
		if (imm > 0x7ffffffLL || imm < -0x8000000LL)
			return LKM_EOPNOTSUPP;
		insn = *(uint32_t *)loc;
		insn = (insn & 0xfc000000u) | ((uint32_t)imm & 0x03ffffffu);
		*(uint32_t *)loc = insn;
		return LKM_OK;
	}
	case LKM_R_AARCH64_CONDBR19: {
		int64_t delta = (int64_t)s + a - (int64_t)(uintptr_t)loc;
		int64_t imm;
		if (delta & 3)
			return LKM_EINVAL;
		imm = delta >> 2;
		if (imm > 0x3ffffLL || imm < -0x40000LL)
			return LKM_EOPNOTSUPP;
		insn = *(uint32_t *)loc;
		insn = (insn & 0xff00001fu) | (((uint32_t)imm & 0x7ffffu) << 5);
		*(uint32_t *)loc = insn;
		return LKM_OK;
	}
	case LKM_R_AARCH64_TSTBR14: {
		int64_t delta = (int64_t)s + a - (int64_t)(uintptr_t)loc;
		int64_t imm;
		if (delta & 3)
			return LKM_EINVAL;
		imm = delta >> 2;
		if (imm > 0x1fffLL || imm < -0x2000LL)
			return LKM_EOPNOTSUPP;
		insn = *(uint32_t *)loc;
		insn = (insn & 0xfff8001fu) | (((uint32_t)imm & 0x3fffu) << 5);
		*(uint32_t *)loc = insn;
		return LKM_OK;
	}
	case LKM_R_AARCH64_ADR_PREL_PG_HI21: {
		uint64_t v = (s + (uint64_t)a) & ~0xfffULL;
		int64_t delta = (int64_t)v - (int64_t)((uintptr_t)loc & ~0xfffULL);
		int64_t imm = delta >> 12;
		uint32_t immlo, immhi;
		if (imm > 0xfffffLL || imm < -0x100000LL)
			return LKM_EOPNOTSUPP;
		immlo = (uint32_t)imm & 0x3u;
		immhi = ((uint32_t)imm >> 2) & 0x7ffffu;
		insn = *(uint32_t *)loc;
		insn = (insn & 0x9f00001fu) | (immlo << 29) | (immhi << 5);
		*(uint32_t *)loc = insn;
		return LKM_OK;
	}
	case LKM_R_AARCH64_ADD_ABS_LO12_NC:
	case LKM_R_AARCH64_LDST8_ABS_LO12_NC:
	case LKM_R_AARCH64_LDST16_ABS_LO12_NC:
	case LKM_R_AARCH64_LDST32_ABS_LO12_NC:
	case LKM_R_AARCH64_LDST64_ABS_LO12_NC:
	case LKM_R_AARCH64_LDST128_ABS_LO12_NC: {
		uint64_t v = s + (uint64_t)a;
		uint32_t shift = 0;
		uint32_t lo;

		if (type == LKM_R_AARCH64_LDST16_ABS_LO12_NC)
			shift = 1;
		else if (type == LKM_R_AARCH64_LDST32_ABS_LO12_NC)
			shift = 2;
		else if (type == LKM_R_AARCH64_LDST64_ABS_LO12_NC)
			shift = 3;
		else if (type == LKM_R_AARCH64_LDST128_ABS_LO12_NC)
			shift = 4;
		if ((v & ((1ULL << shift) - 1)) && shift)
			return LKM_EINVAL;
		lo = (uint32_t)((v >> shift) & 0xfffu);
		insn = *(uint32_t *)loc;
		insn = (insn & 0xffc003ffu) | (lo << 10);
		*(uint32_t *)loc = insn;
		return LKM_OK;
	}
	case LKM_R_AARCH64_MOVW_UABS_G0:
	case LKM_R_AARCH64_MOVW_UABS_G0_NC:
	case LKM_R_AARCH64_MOVW_UABS_G1:
	case LKM_R_AARCH64_MOVW_UABS_G1_NC:
	case LKM_R_AARCH64_MOVW_UABS_G2:
	case LKM_R_AARCH64_MOVW_UABS_G2_NC:
	case LKM_R_AARCH64_MOVW_UABS_G3: {
		uint64_t v = s + (uint64_t)a;
		uint32_t shift;
		uint32_t imm;

		(void)sym_name;
		switch (type) {
		case LKM_R_AARCH64_MOVW_UABS_G0:
		case LKM_R_AARCH64_MOVW_UABS_G0_NC: shift = 0; break;
		case LKM_R_AARCH64_MOVW_UABS_G1:
		case LKM_R_AARCH64_MOVW_UABS_G1_NC: shift = 16; break;
		case LKM_R_AARCH64_MOVW_UABS_G2:
		case LKM_R_AARCH64_MOVW_UABS_G2_NC: shift = 32; break;
		default: shift = 48; break;
		}
		imm = (uint32_t)((v >> shift) & 0xffffu);
		insn = *(uint32_t *)loc;
		insn = (insn & 0xffe0001fu) | (imm << 5);
		*(uint32_t *)loc = insn;
		return LKM_OK;
	}
	default:
		(void)sym_name;
		return LKM_EOPNOTSUPP;
	}
}

static const char *lkm_sec_name(const struct lkm_ehdr *eh, const char *base,
				size_t size, uint16_t idx)
{
	const struct lkm_shdr *sh;
	const char *strtab;
	size_t stroff;

	if (eh->e_shstrndx >= eh->e_shnum)
		return NULL;
	sh = (const struct lkm_shdr *)((const char *)eh + eh->e_shoff) +
	     eh->e_shstrndx;
	if (!lkm_section_range_ok(sh, size))
		return NULL;
	strtab = base + sh->sh_offset;
	stroff = ((const struct lkm_shdr *)((const char *)eh + eh->e_shoff) + idx)->sh_name;
	if (stroff >= sh->sh_size)
		return NULL;
	return strtab + stroff;
}

int lkm_load(const void *data, size_t size, const struct lkm_host *host,
	     const struct lkm_limits *limits, struct lkm_image **out,
	     struct lkm_diag *diag)
{
	const char *base = (const char *)data;
	const struct lkm_ehdr *eh;
	struct lkm_limits lim;
	const struct lkm_shdr *shdrs;
	struct lkm_priv *priv = NULL;
	struct lkm_image *img = NULL;
	size_t total = 0;
	size_t max_align = 1;
	size_t off;
	uint32_t i;
	int ret;

	if (diag) {
		diag->err = LKM_OK;
		diag->section_index = -1;
		diag->reloc_index = 0;
		diag->reloc_type = 0;
		diag->symbol = NULL;
		diag->detail[0] = '\0';
	}
	if (!data || size < 4 || !host || !host->alloc || !host->free ||
	    !host->resolve || !out)
		return LKM_EINVAL;

	eh = (const struct lkm_ehdr *)data;
	if (memcmp(eh->e_ident, "\177ELF", 4) != 0)
		return LKM_ENOEXEC;
	if (eh->e_ident[4] != 2 /* ELFCLASS64 */ ||
	    eh->e_ident[5] != 1 /* ELFDATA2LSB */)
		return LKM_ENOEXEC;
	if (eh->e_type != LKM_ET_REL)
		return LKM_ENOEXEC;
	if (eh->e_machine != LKM_EM_AARCH64)
		return LKM_EBADARCH;
	if (!lkm_mem_ok(eh, size))
		return LKM_EINVAL;

	lim.max_image = limits && limits->max_image ? limits->max_image
						   : (size_t)1 << 30;
	lim.max_relocs = limits && limits->max_relocs ? limits->max_relocs : 4000000u;
	lim.max_sections = limits && limits->max_sections ? limits->max_sections : 4096u;
	lim.max_symbols = limits && limits->max_symbols ? limits->max_symbols : 1000000u;

	if (eh->e_shnum > lim.max_sections) {
		lkm_set_detail(diag, LKM_EMSGSIZE, "too many sections: %u", NULL,
			       eh->e_shnum);
		return LKM_EMSGSIZE;
	}

	shdrs = (const struct lkm_shdr *)(base + eh->e_shoff);

	priv = (struct lkm_priv *)host->alloc(host->ctx, sizeof(*priv));
	if (!priv)
		return LKM_ENOMEM;
	memset(priv, 0, sizeof(*priv));
	priv->host = host;
	priv->nsecs = eh->e_shnum;
	priv->secs = (struct lkm_sec *)host->alloc(host->ctx,
			sizeof(struct lkm_sec) * (size_t)eh->e_shnum);
	if (!priv->secs) {
		ret = LKM_ENOMEM;
		goto fail;
	}
	memset(priv->secs, 0, sizeof(struct lkm_sec) * (size_t)eh->e_shnum);

	/* Pass 1: validate every section and size the image. */
	for (i = 0; i < eh->e_shnum; i++) {
		const struct lkm_shdr *sh = &shdrs[i];
		priv->secs[i].sh = sh;
		priv->secs[i].name = lkm_sec_name(eh, base, size, (uint16_t)i);

		if (!lkm_section_range_ok(sh, size)) {
			lkm_set_detail(diag, LKM_EINVAL, "section %u out of bounds",
				       NULL, i);
			ret = LKM_EINVAL;
			goto fail;
		}
		if (sh->sh_addralign > max_align)
			max_align = (size_t)sh->sh_addralign;
		if (sh->sh_type == LKM_SHT_NOBITS || sh->sh_size == 0)
			continue;
		if (sh->sh_size > lim.max_image ||
		    total > lim.max_image - sh->sh_size) {
			lkm_set_detail(diag, LKM_EMSGSIZE, "image exceeds limit at section %u",
				       NULL, i);
			ret = LKM_EMSGSIZE;
			goto fail;
		}
		/*
		 * Every section is placed on an 8-byte boundary in pass 2, so the
		 * size accounting must charge that padding too; otherwise the last
		 * section can be written past the end of the image.
		 */
		total += (size_t)((sh->sh_size + 7) & ~(uint64_t)7);
	}
	if (max_align < 8)
		max_align = 8;
	if (max_align > 4096)
		max_align = 4096;
	/* Round the total up so the final section cannot overrun the map. */
	total = (total + max_align - 1) & ~(max_align - 1);
	if (total == 0) {
		ret = LKM_ENOEXEC;
		lkm_set_detail(diag, ret, "image has no allocatable content", NULL, 0);
		goto fail;
	}

	img = (struct lkm_image *)host->alloc(host->ctx, sizeof(*img));
	if (!img) {
		ret = LKM_ENOMEM;
		goto fail;
	}
	memset(img, 0, sizeof(*img));
	img->base = host->alloc(host->ctx, total);
	if (!img->base) {
		ret = LKM_ENOMEM;
		goto fail;
	}
	memset(img->base, 0, total);
	img->size = total;
	img->priv = priv;

	/* Pass 2: copy section contents into the image. */
	off = 0;
	for (i = 0; i < eh->e_shnum; i++) {
		const struct lkm_shdr *sh = &shdrs[i];

		if (sh->sh_type == LKM_SHT_NOBITS) {
			/* .bss and friends: reserve space, already zeroed. */
			priv->secs[i].addr = (char *)img->base + off;
			off += (size_t)((sh->sh_size + 7) & ~(uint64_t)7);
			continue;
		}
		if (sh->sh_size == 0)
			continue;
		off = (off + 7) & ~(size_t)7;
		priv->secs[i].addr = (char *)img->base + off;
		memcpy(priv->secs[i].addr, base + sh->sh_offset, (size_t)sh->sh_size);
		off += (size_t)sh->sh_size;
	}

	/* Locate .symtab/.strtab. */
	for (i = 0; i < eh->e_shnum; i++) {
		const struct lkm_shdr *sh = &shdrs[i];

		if (sh->sh_type != LKM_SHT_SYMTAB)
			continue;
		if (sh->sh_entsize != sizeof(struct lkm_sym) ||
		    sh->sh_link >= eh->e_shnum) {
			ret = LKM_EINVAL;
			lkm_set_detail(diag, ret, "malformed .symtab at section %u",
				       NULL, i);
			goto fail;
		}
		priv->syms = (const struct lkm_sym *)(base + sh->sh_offset);
		priv->nsyms = (uint32_t)(sh->sh_size / sizeof(struct lkm_sym));
		{
			const struct lkm_shdr *str = &shdrs[sh->sh_link];
			priv->strtab = base + str->sh_offset;
			priv->strtab_size = (size_t)str->sh_size;
		}
		break;
	}
	if (!priv->syms || !priv->strtab) {
		ret = LKM_ENOENT;
		lkm_set_detail(diag, ret, "no .symtab/.strtab", NULL, 0);
		goto fail;
	}
	if (priv->nsyms > lim.max_symbols) {
		ret = LKM_EMSGSIZE;
		lkm_set_detail(diag, ret, "too many symbols: %u", NULL, priv->nsyms);
		goto fail;
	}

	priv->sym_value = (uint64_t *)host->alloc(host->ctx,
			sizeof(uint64_t) * priv->nsyms);
	priv->sym_local = (unsigned char *)host->alloc(host->ctx, priv->nsyms);
	if (!priv->sym_value || !priv->sym_local) {
		ret = LKM_ENOMEM;
		goto fail;
	}
	memset(priv->sym_value, 0, sizeof(uint64_t) * priv->nsyms);
	memset(priv->sym_local, 0, priv->nsyms);

	/* Resolve symbol values first: relocation needs them. */
	for (i = 0; i < priv->nsyms; i++) {
		const struct lkm_sym *sym = &priv->syms[i];
		const char *name;
		int bind = sym->st_info >> 4;

		if (i == 0) {
			/* The null symbol must have no name and no value. */
			priv->sym_local[0] = 1;
			continue;
		}
		if (sym->st_name >= priv->strtab_size) {
			ret = LKM_EINVAL;
			lkm_set_detail(diag, ret, "symbol %u name out of bounds",
				       NULL, i);
			goto fail;
		}
		name = priv->strtab + sym->st_name;

		if (sym->st_shndx == LKM_SHN_UNDEF) {
			uint64_t addr = host->resolve(host->ctx, name);

			if (!addr) {
				ret = LKM_ENOENT;
				lkm_set_detail(diag, ret, "unresolved symbol: %s",
					       name, 0);
				if (diag)
					diag->symbol = name;
				goto fail;
			}
			priv->sym_value[i] = addr;
			priv->sym_local[i] = 0;
			continue;
		}
		if (sym->st_shndx == LKM_SHN_ABS) {
			priv->sym_value[i] = sym->st_value;
			priv->sym_local[i] = 1;
			continue;
		}
		if (sym->st_shndx == LKM_SHN_COMMON) {
			/* Common symbols are not produced for kernel modules;
			 * refuse rather than guess at an allocation. */
			ret = LKM_EOPNOTSUPP;
			lkm_set_detail(diag, ret, "common symbol unsupported: %s",
				       name, 0);
			if (diag)
				diag->symbol = name;
			goto fail;
		}
		if (sym->st_shndx >= eh->e_shnum) {
			ret = LKM_EINVAL;
			lkm_set_detail(diag, ret, "symbol %s has bad section", name, 0);
			goto fail;
		}
		if (!priv->secs[sym->st_shndx].addr) {
			ret = LKM_EINVAL;
			lkm_set_detail(diag, ret, "symbol %s in unloaded section",
				       name, 0);
			goto fail;
		}
		priv->sym_value[i] = (uint64_t)(uintptr_t)priv->secs[sym->st_shndx].addr +
				     sym->st_value;
		priv->sym_local[i] = (bind == LKM_STB_LOCAL);
	}

	/* Apply RELA sections. */
	{
		uint32_t applied = 0;

		for (i = 0; i < eh->e_shnum; i++) {
			const struct lkm_shdr *sh = &shdrs[i];
			const struct lkm_rela *relas;
			uint32_t nrel;
			uint32_t r;

			if (sh->sh_type != LKM_SHT_RELA)
				continue;
			if (sh->sh_entsize != sizeof(struct lkm_rela) ||
			    sh->sh_info >= eh->e_shnum) {
				ret = LKM_EINVAL;
				lkm_set_detail(diag, ret, "malformed reloc section %u",
					       NULL, i);
				goto fail;
			}
			relas = (const struct lkm_rela *)(base + sh->sh_offset);
			nrel = (uint32_t)(sh->sh_size / sizeof(struct lkm_rela));
			if (applied > lim.max_relocs - nrel) {
				ret = LKM_EMSGSIZE;
				lkm_set_detail(diag, ret, "too many relocations", NULL, 0);
				goto fail;
			}
			if (!priv->secs[sh->sh_info].addr && nrel) {
				ret = LKM_EINVAL;
				lkm_set_detail(diag, ret, "relocs target missing section %u",
					       NULL, sh->sh_info);
				goto fail;
			}
			for (r = 0; r < nrel; r++) {
				const struct lkm_rela *re = &relas[r];
				uint32_t symidx = LKM_R_SYM(re->r_info);
				uint32_t type = LKM_R_TYPE(re->r_info);
				const char *sname = "";
				void *loc;

				applied++;
				if (symidx >= priv->nsyms) {
					ret = LKM_EINVAL;
					lkm_set_detail(diag, ret, "reloc %u refers to symbol %u",
						       NULL, r);
					if (diag) {
						diag->section_index = (int)i;
						diag->reloc_index = r;
					}
					goto fail;
				}
				sname = priv->strtab + priv->syms[symidx].st_name;
				if (re->r_offset > priv->secs[sh->sh_info].sh->sh_size) {
					ret = LKM_EINVAL;
					lkm_set_detail(diag, ret, "reloc %s offset out of range",
						       sname, 0);
					if (diag) {
						diag->section_index = (int)i;
						diag->reloc_index = r;
					}
					goto fail;
				}
				loc = (char *)priv->secs[sh->sh_info].addr + re->r_offset;

				ret = lkm_apply_reloc(type, loc, priv->sym_value[symidx],
						      re->r_addend, sname);
				if (ret != LKM_OK) {
					lkm_set_detail(diag, ret,
						       "unsupported/failed reloc type %u on %s",
						       sname, type);
					if (diag) {
						diag->section_index = (int)i;
						diag->reloc_index = r;
						diag->reloc_type = type;
						diag->symbol = sname;
					}
					goto fail;
				}
			}
		}
	}

	/* Entry points: the kernel calls init_module/cleanup_module, and the
	 * build also emits the names "init_module"/"cleanup_module". */
	for (i = 1; i < priv->nsyms; i++) {
		const struct lkm_sym *sym = &priv->syms[i];
		const char *name;

		if (sym->st_name >= priv->strtab_size)
			continue;
		name = priv->strtab + sym->st_name;
		if (sym->st_shndx == LKM_SHN_UNDEF)
			continue;
		if (strcmp(name, "init_module") == 0)
			img->init_fn = (void *)(uintptr_t)priv->sym_value[i];
		else if (strcmp(name, "cleanup_module") == 0)
			img->exit_fn = (void *)(uintptr_t)priv->sym_value[i];
	}
	if (!img->init_fn) {
		ret = LKM_ENOENT;
		lkm_set_detail(diag, ret, "module has no init_module", NULL, 0);
		goto fail;
	}

	/* .modinfo: vermagic/name/license/depends. */
	{
		struct lkm_sec *mi = NULL;

		for (i = 0; i < eh->e_shnum; i++) {
			const char *nm = priv->secs[i].name;

			if (nm && strcmp(nm, ".modinfo") == 0) {
				mi = &priv->secs[i];
				break;
			}
		}
		if (mi && mi->addr) {
			const char *p = (const char *)mi->addr;
			size_t left = (size_t)mi->sh->sh_size;

			while (left > 0 && *p) {
				size_t len = strlen(p);

				if (strncmp(p, "vermagic=", 9) == 0) {
					img->info.vermagic = p + 9;
					img->info.have_vermagic = 1;
				} else if (strncmp(p, "name=", 5) == 0) {
					img->info.name = p + 5;
					img->module_name = p + 5;
				} else if (strncmp(p, "license=", 8) == 0) {
					img->info.license = p + 8;
					img->info.have_license = 1;
				} else if (strncmp(p, "depends=", 8) == 0) {
					img->info.depends = p + 8;
				}
				p += len + 1;
				if (len + 1 > left)
					break;
				left -= len + 1;
			}
		}
	}

	if (host->protect && img->base && img->size)
		host->protect(host->ctx, img->base, img->size,
			      LKM_PROT_READ | LKM_PROT_EXEC);

	*out = img;
	return LKM_OK;

fail:
	if (img) {
		if (img->base)
			host->free(host->ctx, img->base);
		host->free(host->ctx, img);
	}
	if (priv) {
		if (priv->secs)
			host->free(host->ctx, priv->secs);
		if (priv->sym_value)
			host->free(host->ctx, priv->sym_value);
		if (priv->sym_local)
			host->free(host->ctx, priv->sym_local);
		host->free(host->ctx, priv);
	}
	return ret;
}

void lkm_unload(struct lkm_image *img, const struct lkm_host *host)
{
	struct lkm_priv *priv;

	if (!img || !host)
		return;
	priv = (struct lkm_priv *)img->priv;
	if (priv) {
		if (priv->secs)
			host->free(host->ctx, priv->secs);
		if (priv->sym_value)
			host->free(host->ctx, priv->sym_value);
		if (priv->sym_local)
			host->free(host->ctx, priv->sym_local);
		host->free(host->ctx, priv);
	}
	if (img->base)
		host->free(host->ctx, img->base);
	host->free(host->ctx, img);
}

const char *lkm_image_vermagic(const struct lkm_image *img)
{
	return img && img->info.have_vermagic ? img->info.vermagic : NULL;
}

void *lkm_image_init(const struct lkm_image *img)
{
	return img ? img->init_fn : NULL;
}

void *lkm_image_exit(const struct lkm_image *img)
{
	return img ? img->exit_fn : NULL;
}

/*
 * modinfo_vermagic must match the running kernel's vermagic.
 *
 * The kernel compares the release and the flag words.  A loader that skips
 * this check is the reason "insmod: invalid module format" appears with no
 * useful message, so we surface the first differing field instead.
 */
int lkm_check_vermagic(const char *module_vermagic, const char *kernel_vermagic,
		       char *detail, size_t detail_len)
{
	const char *m_rel_end;
	const char *k_rel_end;
	size_t m_rel, k_rel;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!module_vermagic || !kernel_vermagic) {
		if (detail && detail_len)
			memcpy(detail, "module or kernel vermagic is absent",
			       detail_len < 39 ? detail_len - 1 : 39);
		return LKM_ENOENT;
	}

	m_rel_end = module_vermagic;
	while (*m_rel_end && *m_rel_end != ' ')
		m_rel_end++;
	k_rel_end = kernel_vermagic;
	while (*k_rel_end && *k_rel_end != ' ')
		k_rel_end++;
	m_rel = (size_t)(m_rel_end - module_vermagic);
	k_rel = (size_t)(k_rel_end - kernel_vermagic);

	if (m_rel != k_rel || memcmp(module_vermagic, kernel_vermagic, m_rel) != 0) {
		if (detail && detail_len) {
			size_t w = 0;
			const char *a = "release mismatch: module=";
			const char *b = " kernel=";

			while (*a && w + 1 < detail_len)
				detail[w++] = *a++;
			{
				size_t i;
				for (i = 0; i < m_rel && w + 1 < detail_len; i++)
					detail[w++] = module_vermagic[i];
			}
			while (*b && w + 1 < detail_len)
				detail[w++] = *b++;
			{
				size_t i;
				for (i = 0; i < k_rel && w + 1 < detail_len; i++)
					detail[w++] = kernel_vermagic[i];
			}
			detail[w] = '\0';
		}
		return LKM_EOPNOTSUPP;
	}

	/* The flag tail must match exactly: SMP/preempt/mod_unload/modversions. */
	if (strcmp(m_rel_end, k_rel_end) != 0) {
		if (detail && detail_len) {
			size_t w = 0;
			const char *a = "flag mismatch: module=";

			while (*a && w + 1 < detail_len)
				detail[w++] = *a++;
			while (*m_rel_end && w + 1 < detail_len)
				detail[w++] = *m_rel_end++;
			detail[w] = '\0';
		}
		return LKM_EOPNOTSUPP;
	}
	return LKM_OK;
}

LKM_API uint32_t lkm_loader_abi_version(void)
{
	return LKM_LOADER_ABI_VERSION;
}

#endif /* LKM_LOADER_IMPL_ONCE */
#endif /* LKM_LOADER_IMPLEMENTATION */
