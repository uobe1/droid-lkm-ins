/* SPDX-License-Identifier: GPL-2.0-only
 *
 * lkm_kallsyms.h - the symbol provider lkm_bind.h needs, plus the load step.
 *
 * Reading /proc/kallsyms is the part both references get subtly right, so the
 * rules are written down here rather than rediscovered:
 *
 *   - /proc/kallsyms reports 0000000000000000 for every address while
 *     kptr_restrict is 2 (and for non-root while it is 1).  APatch lowers it to
 *     1 for the duration of the read and restores the old value on the way out;
 *     we do the same, including on the error paths.
 *   - the file lists kernel symbols first and module symbols after.  Stop at the
 *     first line that has a fourth column (the module name), so a module's
 *     symbol can never shadow a kernel symbol of the same name.
 *   - names carry compiler suffixes.  Folding happens in lkm_strip_symbol_suffix.
 *
 * The load step is the kernel's: init_module(2) with the patched image.  There
 * is no in-kernel relocation here by design -- see the note at the top of
 * lkm_bind.h.
 */
#ifndef LKM_KALLSYMS_H
#define LKM_KALLSYMS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lkm_bind.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * No artificial symbol cap.  A real GKI kernel exports on the order of 300k
 * kallsyms entries; truncating at some round number silently turns "symbol not
 * built" into "symbol not found" and the bind then reports a module as
 * unloadable for the wrong reason.  The table is grown until allocation fails,
 * and ENOMEM is reported honestly.
 */
#define LKM_SYMBOL_NAME_MAX 128

struct lkm_kallsym {
	char name[LKM_SYMBOL_NAME_MAX];
	uint64_t addr;
};

struct lkm_kallsyms {
	struct lkm_kallsym *syms;
	uint32_t count;
	uint32_t cap;
	uint32_t truncated; /* hit the cap: the table is incomplete */
};

/*
 * Reader hook so the same code runs on a host under test and on the device.
 * `read_file` returns the file contents in a malloc'd buffer, or NULL.
 */
struct lkm_fs {
	void *ctx;
	char *(*read_file)(void *ctx, const char *path, size_t *len);
	int (*write_file)(void *ctx, const char *path, const char *value);
};

/* Simple stdio implementation, for host tests. */
LKM_BIND_API char *lkm_fs_read_file(void *ctx, const char *path, size_t *len);
LKM_BIND_API int lkm_fs_write_file(void *ctx, const char *path, const char *value);

/*
 * Parse a /proc/kallsyms image already in memory.  Returns the number of symbols
 * stored, or a negative LKM_BIND_* code.  Kept separate from the file I/O so it
 * can be tested without /proc.
 */
LKM_BIND_API int lkm_kallsyms_parse(const char *text, size_t len, struct lkm_kallsyms *out);

/* Read and parse /proc/kallsyms through `fs`, handling kptr_restrict. */
LKM_BIND_API int lkm_kallsyms_load(const struct lkm_fs *fs, struct lkm_kallsyms *out);

LKM_BIND_API void lkm_kallsyms_free(struct lkm_kallsyms *ks);

/* Provider that lkm_bind.h consumes. */
struct lkm_kallsyms_lookup_ctx {
	const struct lkm_kallsyms *ks;
	uint32_t misses;
};

LKM_BIND_API uint64_t lkm_kallsyms_lookup(void *ctx, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* LKM_KALLSYMS_H */

/* ====================================================================== */
#ifdef LKM_KALLSYMS_IMPLEMENTATION
#ifndef LKM_KALLSYMS_IMPL_ONCE
#define LKM_KALLSYMS_IMPL_ONCE

#include <stdio.h>
#include <stdlib.h>

/*
 * Read a whole file by streaming.
 *
 * /proc entries are synthetic: fseek(SEEK_END) reports 0 and ftell gives a
 * length that has nothing to do with the content, so a size-then-read approach
 * silently returns an empty buffer for /proc/kallsyms.  Read in chunks and grow
 * instead; that works for real files and for proc files alike.
 */
LKM_BIND_API char *lkm_fs_read_file(void *ctx, const char *path, size_t *len)
{
	FILE *f;
	char *buf = NULL;
	size_t cap = 0, used = 0;

	(void)ctx;
	if (len)
		*len = 0;
	f = fopen(path, "rb");
	if (!f)
		return NULL;

	for (;;) {
		size_t got;

		if (cap - used < 4096) {
			size_t newcap = cap ? cap * 2 : 65536;
			char *grown = realloc(buf, newcap + 1);

			if (!grown) {
				free(buf);
				fclose(f);
				return NULL;
			}
			buf = grown;
			cap = newcap;
		}
		got = fread(buf + used, 1, cap - used, f);
		used += got;
		if (got == 0)
			break;
	}
	if (ferror(f)) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	if (!buf) {
		buf = malloc(1);
		if (!buf)
			return NULL;
	}
	buf[used] = '\0';
	if (len)
		*len = used;
	return buf;
}

LKM_BIND_API int lkm_fs_write_file(void *ctx, const char *path, const char *value)
{
	FILE *f;

	(void)ctx;
	f = fopen(path, "w");
	if (!f)
		return LKM_BIND_ENOENT;
	if (fputs(value, f) < 0) {
		fclose(f);
		return LKM_BIND_EINVAL;
	}
	fclose(f);
	return LKM_BIND_OK;
}

static int lkm_hex_to_u64(const char *s, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;

	if (!n || n > 16)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		unsigned int d;

		if (c >= '0' && c <= '9')
			d = c - '0';
		else if (c >= 'a' && c <= 'f')
			d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			d = c - 'A' + 10;
		else
			return 0;
		v = (v << 4) | d;
	}
	*out = v;
	return 1;
}

LKM_BIND_API int lkm_kallsyms_parse(const char *text, size_t len, struct lkm_kallsyms *out)
{
	size_t pos = 0;

	if (!text || !out)
		return LKM_BIND_EINVAL;
	memset(out, 0, sizeof(*out));

	while (pos < len) {
		size_t line_end = pos;
		size_t start[4], end[4];
		size_t nfields = 0;
		size_t p, name_start = 0, name_len = 0;
		uint64_t addr = 0;

		while (line_end < len && text[line_end] != '\n')
			line_end++;

		/*
		 * Split the line into whitespace-separated fields, recording both
		 * ends.  Recording only the start would hand the decimal/hex parser a
		 * token with a trailing space, and every address would be rejected.
		 */
		p = pos;
		while (p < line_end && nfields < 4) {
			while (p < line_end && (text[p] == ' ' || text[p] == '\t'))
				p++;
			if (p >= line_end)
				break;
			start[nfields] = p;
			while (p < line_end && text[p] != ' ' && text[p] != '\t')
				p++;
			end[nfields] = p;
			nfields++;
		}

		pos = line_end + 1;

		/* addr type name [module] -- a fourth field means a module symbol,
		 * and the kernel list is over: stop here. */
		if (nfields >= 4)
			break;
		if (nfields < 3)
			continue;

		name_start = start[2];
		name_len = end[2] - start[2];
		if (!name_len || name_len >= LKM_SYMBOL_NAME_MAX)
			continue;
		if (!lkm_hex_to_u64(text + start[0], end[0] - start[0], &addr))
			continue;
		/* Zero addresses appear when kptr_restrict defeated the read; such a
		 * table is useless and must not be mistaken for "symbol not found". */
		if (!addr)
			continue;

		if (out->count == out->cap) {
			uint32_t newcap = out->cap ? out->cap * 2 : 4096;
			struct lkm_kallsym *grown;

			grown = realloc(out->syms, (size_t)newcap * sizeof(*grown));
			if (!grown)
				return LKM_BIND_ENOMEM;
			out->syms = grown;
			out->cap = newcap;
		}
		memcpy(out->syms[out->count].name, text + name_start, name_len);
		out->syms[out->count].name[name_len] = '\0';
		out->syms[out->count].addr = addr;
		out->count++;
	}

	if (!out->count)
		return LKM_BIND_ENOENT;
	return (int)out->count;
}

LKM_BIND_API int lkm_kallsyms_load(const struct lkm_fs *fs, struct lkm_kallsyms *out)
{
	char *text;
	char old[16];
	size_t len = 0;
	int ret;
	int relaxed = 0;

	if (!fs || !fs->read_file || !out)
		return LKM_BIND_EINVAL;

	/*
	 * Relax kptr_restrict only when we can put it back.  With no writer we try
	 * anyway: on a root shell that already has addresses this is a no-op, and
	 * on a locked-down host the parse will report zero addresses and fail
	 * loudly rather than binding garbage.
	 */
	if (fs->write_file && fs->read_file) {
		size_t got = 0;
		char *cur = fs->read_file(fs->ctx, "/proc/sys/kernel/kptr_restrict", &got);

		if (cur) {
			size_t n = 0;

			while (n < got && n < sizeof(old) - 1 && cur[n] != '\n' && cur[n] != '\0') {
				old[n] = cur[n];
				n++;
			}
			old[n] = '\0';
			free(cur);
			if (fs->write_file(fs->ctx, "/proc/sys/kernel/kptr_restrict", "1") ==
			    LKM_BIND_OK)
				relaxed = 1;
		}
	}

	text = fs->read_file(fs->ctx, "/proc/kallsyms", &len);
	ret = text ? lkm_kallsyms_parse(text, len, out) : LKM_BIND_ENOENT;
	free(text);

	/*
	 * kptr_restrict is a security setting, so leaving it relaxed is worse than
	 * failing the load: report the failure instead of pretending the read was
	 * side-effect free.  The restore is retried once before giving up.
	 */
	if (relaxed &&
	    fs->write_file(fs->ctx, "/proc/sys/kernel/kptr_restrict", old) != LKM_BIND_OK &&
	    fs->write_file(fs->ctx, "/proc/sys/kernel/kptr_restrict", old) != LKM_BIND_OK) {
		lkm_kallsyms_free(out);
		memset(out, 0, sizeof(*out));
		return LKM_BIND_EIO;
	}
	return ret;
}

LKM_BIND_API void lkm_kallsyms_free(struct lkm_kallsyms *ks)
{
	if (!ks)
		return;
	free(ks->syms);
	memset(ks, 0, sizeof(*ks));
}

LKM_BIND_API uint64_t lkm_kallsyms_lookup(void *ctx, const char *name)
{
	struct lkm_kallsyms_lookup_ctx *lc = ctx;
	uint32_t i;

	if (!lc || !lc->ks || !name)
		return 0;
	/* /proc/kallsyms is address-ordered, not name-ordered, so this is a scan.
	 * It runs once per undefined symbol, which is a few hundred at most. */
	for (i = 0; i < lc->ks->count; i++) {
		if (!strcmp(lc->ks->syms[i].name, name))
			return lc->ks->syms[i].addr;
	}
	lc->misses++;
	return 0;
}

#endif /* LKM_KALLSYMS_IMPL_ONCE */
#endif /* LKM_KALLSYMS_IMPLEMENTATION */
