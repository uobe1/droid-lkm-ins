/* SPDX-License-Identifier: GPL-2.0-only
 *
 * lkm_insmod.c - path canonicalization, vermagic extraction/rewrite, and the
 * one-shot retry used by `lkmctl insmod`.
 *
 * The reference shape is KernelSU's ksuinit: open the kernel log at its end
 * before the first attempt, read only the records the failed load produced,
 * take the last "version magic 'X' should be 'Y'" record, rewrite .modinfo to
 * Y, and try once more.  APatch's apd is the other reference for the parts it
 * has: canonicalize the module path, join parameters with spaces, print
 * "Loaded kernel module: <path>" on success.
 *
 * Two deliberate differences from a blind port:
 *
 *   - .modinfo is located through the ELF section table, so a "vermagic=" byte
 *     sequence in some unrelated section is never rewritten.
 *   - every failure path explains itself.  A retry that could not happen (no
 *     log, no record, no room) is reported as the original ENOEXEC with the
 *     reason, never as a success and never as a silent second attempt.
 */
#define _GNU_SOURCE
#include "lkm_insmod.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ELF section type with no file contents; <elf.h> is deliberately not used. */
#define LKM_SHT_NOBITS 8

/* ---- owned image buffer ------------------------------------------------- */

void lkm_buffer_init(struct lkm_buffer *buf)
{
	if (!buf)
		return;
	buf->data = NULL;
	buf->len = 0;
	buf->cap = 0;
}

void lkm_buffer_free(struct lkm_buffer *buf)
{
	if (!buf)
		return;
	free(buf->data);
	lkm_buffer_init(buf);
}

int lkm_buffer_reserve(struct lkm_buffer *buf, size_t need)
{
	size_t cap;
	void *grown;

	if (!buf)
		return EINVAL;
	if (need <= buf->cap)
		return 0;

	cap = buf->cap ? buf->cap : 4096;
	while (cap < need) {
		if (cap > SIZE_MAX / 2) {
			cap = need;
			break;
		}
		cap *= 2;
	}
	grown = realloc(buf->data, cap);
	if (!grown)
		return ENOMEM;
	buf->data = grown;
	buf->cap = cap;
	return 0;
}

int lkm_buffer_read_file(struct lkm_buffer *buf, const char *path, char *detail, size_t detail_len)
{
	int fd;
	int saved;
	size_t len = 0;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!buf || !path || !*path) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "empty module path");
		return EINVAL;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		saved = errno;
		if (detail && detail_len)
			snprintf(detail, detail_len, "cannot open %s: %s", path, strerror(saved));
		return saved;
	}

	for (;;) {
		ssize_t n;

		if (len == buf->cap) {
			if (lkm_buffer_reserve(buf, len + 8192) != 0) {
				close(fd);
				if (detail && detail_len)
					snprintf(detail, detail_len, "out of memory reading %s",
						 path);
				return ENOMEM;
			}
		}
		n = read(fd, buf->data + len, buf->cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			saved = errno;
			close(fd);
			if (detail && detail_len)
				snprintf(detail, detail_len, "cannot read %s: %s", path,
					 strerror(saved));
			return saved;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	close(fd);

	buf->len = len;
	if (len == 0) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "%s is empty; not a kernel module", path);
		return ENOEXEC;
	}
	return 0;
}

/* ---- path canonicalization --------------------------------------------- */

int lkm_canonicalize_path(const char *path, char *out, size_t out_len)
{
	char resolved[PATH_MAX];
	size_t n;

	if (!path || !*path || !out || out_len == 0)
		return EINVAL;
	errno = 0;
	if (!realpath(path, resolved))
		return errno ? errno : ENOENT;
	n = strlen(resolved);
	if (n + 1 > out_len)
		return ENAMETOOLONG;
	memcpy(out, resolved, n + 1);
	return 0;
}

/* ---- minimal ELF64 parsing (no <elf.h>, little or big endian) ---------- */

struct lkm_modinfo_sec {
	size_t hdr_off; /* section header offset inside the image */
	size_t off;
	size_t size;
	size_t align;
	int little_endian;
};

static uint16_t get16(const unsigned char *p, int le)
{
	if (le)
		return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
	return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t get32(const unsigned char *p, int le)
{
	uint32_t v = 0;
	int i;

	for (i = 0; i < 4; i++) {
		if (le)
			v |= (uint32_t)p[i] << (8 * i);
		else
			v = (v << 8) | p[i];
	}
	return v;
}

static uint64_t get64(const unsigned char *p, int le)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 8; i++) {
		if (le)
			v |= (uint64_t)p[i] << (8 * i);
		else
			v = (v << 8) | p[i];
	}
	return v;
}

static void put64(unsigned char *p, uint64_t v, int le)
{
	int i;

	for (i = 0; i < 8; i++) {
		if (le)
			p[i] = (unsigned char)(v >> (8 * i));
		else
			p[7 - i] = (unsigned char)(v >> (8 * i));
	}
}

static int elf_find_modinfo(const unsigned char *data, size_t len, struct lkm_modinfo_sec *sec,
			    char *detail, size_t detail_len)
{
	uint64_t shoff, str_off, str_size;
	uint16_t shentsize, shnum, shstrndx;
	size_t i;
	int le;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!data || !sec)
		return EINVAL;
	if (len < 64) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "truncated ELF header");
		return ENOEXEC;
	}
	if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
		if (detail && detail_len)
			snprintf(detail, detail_len, "not an ELF image");
		return ENOEXEC;
	}
	if (data[4] != 2) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "not an ELF64 image (class %u)", data[4]);
		return ENOEXEC;
	}
	if (data[5] != 1 && data[5] != 2) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "invalid ELF data encoding %u", data[5]);
		return ENOEXEC;
	}
	le = data[5] == 1;

	shoff = get64(data + 40, le);
	shentsize = get16(data + 58, le);
	shnum = get16(data + 60, le);
	shstrndx = get16(data + 62, le);

	if (shoff == 0 || shnum == 0 || shentsize < 64) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "no usable section header table");
		return ENOEXEC;
	}
	if (shoff > len || (uint64_t)shnum > (len - (size_t)shoff) / shentsize) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "section header table is outside the image");
		return ENOEXEC;
	}
	if (shstrndx >= shnum) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "extended section numbering is unsupported");
		return ENOEXEC;
	}

	{
		size_t hdr = (size_t)shoff + (size_t)shstrndx * shentsize;

		str_off = get64(data + hdr + 24, le);
		str_size = get64(data + hdr + 32, le);
	}
	if (str_off > len || str_size > len - (size_t)str_off) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "section name table is outside the image");
		return ENOEXEC;
	}

	for (i = 0; i < shnum; i++) {
		size_t hdr = (size_t)shoff + i * shentsize;
		uint32_t name = get32(data + hdr, le);
		const char *s;
		size_t max;

		if (name >= str_size)
			continue;
		s = (const char *)data + str_off + name;
		max = (size_t)str_size - name;
		if (strnlen(s, max) == max)
			continue;
		if (strcmp(s, ".modinfo") != 0)
			continue;

		sec->hdr_off = hdr;
		sec->off = (size_t)get64(data + hdr + 24, le);
		sec->size = (size_t)get64(data + hdr + 32, le);
		sec->align = (size_t)get64(data + hdr + 48, le);
		sec->little_endian = le;

		if (sec->off > len || sec->size > len - sec->off) {
			if (detail && detail_len)
				snprintf(detail, detail_len, ".modinfo is outside the image");
			return ENOEXEC;
		}
		if (sec->align == 0)
			sec->align = 1;
		if ((sec->align & (sec->align - 1)) != 0) {
			if (detail && detail_len)
				snprintf(detail, detail_len, "invalid .modinfo alignment %zu",
					 sec->align);
			return ENOEXEC;
		}
		return 0;
	}

	if (detail && detail_len)
		snprintf(detail, detail_len, "module has no .modinfo section");
	return ENOENT;
}

int lkm_modinfo_get(const unsigned char *data, size_t len, const char *key, char *out,
		    size_t out_len)
{
	struct lkm_modinfo_sec sec;
	const unsigned char *p;
	size_t left, key_len;
	int rc;

	if (!data || !key || !*key || !out || out_len == 0)
		return EINVAL;
	rc = elf_find_modinfo(data, len, &sec, NULL, 0);
	if (rc)
		return rc;

	key_len = strlen(key);
	p = data + sec.off;
	left = sec.size;
	while (left > 0) {
		size_t n = strnlen((const char *)p, left);

		if (n >= key_len + 1 && !memcmp(p, key, key_len) && p[key_len] == '=') {
			size_t vlen = n - key_len - 1;

			if (vlen + 1 > out_len)
				return ENAMETOOLONG;
			memcpy(out, p + key_len + 1, vlen);
			out[vlen] = '\0';
			return 0;
		}
		if (n == left)
			break; /* unterminated last entry: nothing more follows */
		p += n + 1;
		left -= n + 1;
	}
	return ENOENT;
}

/* ---- kernel-log vermagic extraction ------------------------------------ */

static const char *find_sub(const char *hay, size_t hay_len, const char *needle)
{
	size_t needle_len = strlen(needle);
	size_t i;

	if (needle_len == 0 || hay_len < needle_len)
		return NULL;
	for (i = 0; i + needle_len <= hay_len; i++)
		if (hay[i] == needle[0] && memcmp(hay + i, needle, needle_len) == 0)
			return hay + i;
	return NULL;
}

int lkm_extract_required_vermagic(const char *log_text, size_t log_len, char *out, size_t out_len)
{
	static const char prefix[] = "version magic '";
	static const char separator[] = "' should be '";
	size_t pos = 0;
	int found = 0;

	if (!log_text || !out || out_len == 0)
		return EINVAL;
	if (out_len > 0)
		out[0] = '\0';

	while (pos < log_len) {
		const char *line = log_text + pos;
		const char *newline = memchr(line, '\n', log_len - pos);
		size_t line_len = newline ? (size_t)(newline - line) : log_len - pos;
		const char *msg = line;
		size_t msg_len = line_len;
		const char *semi = memchr(line, ';', line_len);

		if (semi) {
			/* Skip "<prio>,<seq>,<usec>,<flags>;" of a kmsg record. */
			msg = semi + 1;
			msg_len = line_len - (size_t)(msg - line);
		}

		{
			const char *p = find_sub(msg, msg_len, prefix);

			if (p) {
				size_t after = (size_t)(p - msg) + strlen(prefix);
				const char *q = find_sub(msg + after, msg_len - after, separator);

				if (q) {
					size_t rstart = (size_t)(q - msg) + strlen(separator);
					const char *r = msg + rstart;
					size_t rleft = msg_len - rstart;
					const char *end = memchr(r, '\'', rleft);

					if (end && end != r) {
						size_t rlen = (size_t)(end - r);

						if (rlen + 1 > out_len)
							return ENAMETOOLONG;
						memcpy(out, r, rlen);
						out[rlen] = '\0';
						found = 1;
					}
				}
			}
		}

		if (!newline)
			break;
		pos += line_len + 1;
	}
	return found ? 0 : ENOENT;
}

/* ---- vermagic rewrite --------------------------------------------------- */

int lkm_rewrite_vermagic(struct lkm_buffer *buf, const char *required, char *detail,
			 size_t detail_len)
{
	struct lkm_modinfo_sec sec;
	unsigned char *fresh = NULL;
	const unsigned char *p;
	size_t left, req_len, cap, fresh_len = 0, off, need;
	int replaced = 0;
	int rc;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!buf || !buf->data || buf->len == 0 || !required || !*required) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "no image or no required vermagic");
		return EINVAL;
	}
	req_len = strlen(required);
	if (req_len >= LKM_INSMOD_VERMAGIC_MAX) {
		if (detail && detail_len)
			snprintf(detail, detail_len,
				 "required vermagic is %zu bytes; refusing to "
				 "grow .modinfo past %d",
				 req_len, LKM_INSMOD_VERMAGIC_MAX - 1);
		return EINVAL;
	}

	rc = elf_find_modinfo(buf->data, buf->len, &sec, detail, detail_len);
	if (rc)
		return rc;

	/* Rebuild the section: every entry kept, the first vermagic= replaced
	 * (or appended when absent).  Bound: old size + new entry + NULs. */
	if (sec.size > SIZE_MAX - req_len - 16) {
		if (detail && detail_len)
			snprintf(detail, detail_len, ".modinfo size overflow");
		return EOVERFLOW;
	}
	cap = sec.size + req_len + 16;
	fresh = malloc(cap);
	if (!fresh) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "out of memory rebuilding .modinfo");
		return ENOMEM;
	}

	p = buf->data + sec.off;
	left = sec.size;
	while (left > 0) {
		size_t n = strnlen((const char *)p, left);
		size_t write_len = n;

		if (!replaced && n >= 9 && !memcmp(p, "vermagic=", 9)) {
			write_len = 9 + req_len;
			if (fresh_len + write_len + 1 > cap)
				goto overflow;
			memcpy(fresh + fresh_len, "vermagic=", 9);
			memcpy(fresh + fresh_len + 9, required, req_len);
			fresh_len += write_len;
			fresh[fresh_len++] = '\0';
			replaced = 1;
		} else {
			if (fresh_len + write_len + 1 > cap)
				goto overflow;
			memcpy(fresh + fresh_len, p, write_len);
			fresh_len += write_len;
			fresh[fresh_len++] = '\0';
		}
		if (n == left)
			break; /* unterminated last entry: terminate it */
		p += n + 1;
		left -= n + 1;
	}

	if (!replaced) {
		size_t write_len = 9 + req_len;

		if (fresh_len + write_len + 1 > cap)
			goto overflow;
		memcpy(fresh + fresh_len, "vermagic=", 9);
		memcpy(fresh + fresh_len + 9, required, req_len);
		fresh_len += write_len;
		fresh[fresh_len++] = '\0';
	}

	/* Append the new section copy, aligned as the section requires.  The
	 * old bytes stay where they are; only the section header moves. */
	if (buf->len > SIZE_MAX - sec.align) {
		rc = EOVERFLOW;
		if (detail && detail_len)
			snprintf(detail, detail_len, "image size overflow");
		goto out;
	}
	off = (buf->len + sec.align - 1) & ~(sec.align - 1);
	if (off > SIZE_MAX - fresh_len) {
		rc = EOVERFLOW;
		if (detail && detail_len)
			snprintf(detail, detail_len, "image size overflow");
		goto out;
	}
	need = off + fresh_len;
	rc = lkm_buffer_reserve(buf, need);
	if (rc) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "out of memory growing the image by %zu bytes",
				 fresh_len);
		goto out;
	}
	if (off > buf->len)
		memset(buf->data + buf->len, 0, off - buf->len);
	memcpy(buf->data + off, fresh, fresh_len);
	buf->len = need;
	put64(buf->data + sec.hdr_off + 24, off, sec.little_endian);
	put64(buf->data + sec.hdr_off + 32, fresh_len, sec.little_endian);
	rc = 0;
	goto out;

overflow:
	rc = ENOMEM;
	if (detail && detail_len)
		snprintf(detail, detail_len, "internal .modinfo size accounting failed");
out:
	free(fresh);
	return rc;
}

/* ---- kernel BTF layout and module ABI adaptation ------------------------ */

/*
 * The kernel's `struct module` layout is not part of the module's ELF data
 * itself; it comes from the headers the module was built against.  A module
 * built against different headers can therefore load but have its init/exit
 * read from the wrong offsets (the observed failure: exit read as NULL, so the
 * kernel marked the module [permanent] and refused to unload it).
 *
 * Read the running kernel's real layout from BTF and rewrite the module's
 * .gnu.linkonce.this_module section and its relocations to match.  This is what
 * makes one loader work across kernels with different struct-module layouts.
 */

struct lkm_elf_sec {
	size_t index;
	size_t hdr_off;
	size_t off;
	size_t size;
	size_t align;
	uint32_t type;
	uint32_t link;
	uint32_t info;
	uint64_t entsize;
	int little_endian;
};

struct lkm_elf_hdr {
	size_t shoff;
	size_t shentsize;
	size_t shnum;
	size_t shstrndx;
	int little_endian;
};

static int elf_parse_header(const unsigned char *data, size_t len, struct lkm_elf_hdr *hdr,
			    char *detail, size_t detail_len)
{
	uint64_t shoff;
	uint16_t shentsize, shnum, shstrndx;
	int le;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!data || !hdr)
		return EINVAL;
	if (len < 64) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "truncated ELF header");
		return ENOEXEC;
	}
	if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' || data[4] != 2 ||
	    (data[5] != 1 && data[5] != 2)) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "not a usable ELF64 image");
		return ENOEXEC;
	}
	le = data[5] == 1;
	shoff = get64(data + 40, le);
	shentsize = get16(data + 58, le);
	shnum = get16(data + 60, le);
	shstrndx = get16(data + 62, le);

	if (shoff == 0 || shnum == 0 || shentsize < 64) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "no usable section header table");
		return ENOEXEC;
	}
	if (shoff > len || (uint64_t)shnum > (len - (size_t)shoff) / shentsize ||
	    shstrndx >= shnum) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "unusable section header table");
		return ENOEXEC;
	}
	hdr->shoff = (size_t)shoff;
	hdr->shentsize = shentsize;
	hdr->shnum = shnum;
	hdr->shstrndx = shstrndx;
	hdr->little_endian = le;
	return 0;
}

static int elf_section_at(const unsigned char *data, size_t len, const struct lkm_elf_hdr *hdr,
			  size_t index, struct lkm_elf_sec *sec, char *detail, size_t detail_len)
{
	size_t h;

	if (!data || !hdr || !sec || index >= hdr->shnum)
		return EINVAL;
	h = hdr->shoff + index * hdr->shentsize;
	if (h + 64 > len) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "section header %zu outside the image", index);
		return ENOEXEC;
	}
	sec->index = index;
	sec->hdr_off = h;
	sec->type = get32(data + h + 4, hdr->little_endian);
	sec->off = (size_t)get64(data + h + 24, hdr->little_endian);
	sec->size = (size_t)get64(data + h + 32, hdr->little_endian);
	sec->link = get32(data + h + 40, hdr->little_endian);
	sec->info = get32(data + h + 44, hdr->little_endian);
	sec->align = (size_t)get64(data + h + 48, hdr->little_endian);
	sec->entsize = get64(data + h + 56, hdr->little_endian);
	sec->little_endian = hdr->little_endian;
	if (sec->align == 0)
		sec->align = 1;
	/*
	 * SHT_NOBITS (e.g. .bss) has no file contents: sh_offset/sh_size describe
	 * memory, not bytes in the image.  A real .ko's .bss is normally placed
	 * before .gnu.linkonce.this_module, and a large one would otherwise look
	 * like a truncated image.  The kernel skips the same sections for the
	 * same reason (kernel/module/main.c, elf_validity_check).
	 */
	if (sec->type != LKM_SHT_NOBITS && (sec->off > len || sec->size > len - sec->off)) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "section %zu outside the image", index);
		return ENOEXEC;
	}
	return 0;
}

static int elf_section_by_index(const unsigned char *data, size_t len,
				const struct lkm_elf_hdr *hdr, size_t index,
				struct lkm_elf_sec *sec, char *detail, size_t detail_len)
{
	return elf_section_at(data, len, hdr, index, sec, detail, detail_len);
}

static int elf_find_section(const unsigned char *data, size_t len, const char *wanted,
			    struct lkm_elf_sec *sec, char *detail, size_t detail_len)
{
	struct lkm_elf_hdr hdr;
	struct lkm_elf_sec str;
	const char *name;
	size_t i, max;
	int rc;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!data || !wanted || !sec)
		return EINVAL;
	rc = elf_parse_header(data, len, &hdr, detail, detail_len);
	if (rc)
		return rc;
	rc = elf_section_by_index(data, len, &hdr, hdr.shstrndx, &str, detail, detail_len);
	if (rc)
		return rc;
	if (str.size == 0) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "empty section name table");
		return ENOEXEC;
	}

	for (i = 0; i < hdr.shnum; i++) {
		struct lkm_elf_sec cur;
		uint32_t name_off;

		rc = elf_section_at(data, len, &hdr, i, &cur, detail, detail_len);
		if (rc)
			return rc;
		name_off = get32(data + cur.hdr_off, hdr.little_endian);
		if (name_off >= str.size)
			continue;
		name = (const char *)data + str.off + name_off;
		max = str.size - name_off;
		if (strnlen(name, max) == max)
			continue;
		if (strcmp(name, wanted) != 0)
			continue;
		*sec = cur;
		return 0;
	}
	if (detail && detail_len)
		snprintf(detail, detail_len, "module has no %s section", wanted);
	return ENOENT;
}

static uint32_t btf_u32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static size_t btf_payload(int kind, uint32_t vlen)
{
	switch (kind) {
	case 1: /* INT */
		return 4;
	case 3: /* ARRAY */
		return 12;
	case 4: /* STRUCT */
	case 5: /* UNION */
		return (size_t)vlen * 12;
	case 6: /* ENUM */
		return (size_t)vlen * 8;
	case 13: /* FUNC_PROTO */
		return (size_t)vlen * 8;
	case 14: /* VAR */
		return 4;
	case 15: /* DATASEC */
		return (size_t)vlen * 12;
	case 17: /* DECL_TAG */
		return 4;
	case 19: /* ENUM64 */
		return (size_t)vlen * 12;
	default:
		return 0;
	}
}

int lkm_btf_module_layout(const char *btf_path, struct lkm_module_layout *layout, char *detail,
			  size_t detail_len)
{
	struct lkm_buffer b;
	const unsigned char *types, *strs;
	size_t type_len, str_len, pos;
	uint32_t hdr_len, type_off, str_off;
	int rc;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!btf_path || !layout)
		return EINVAL;
	memset(layout, 0, sizeof(*layout));
	layout->exit_off = SIZE_MAX;

	lkm_buffer_init(&b);
	rc = lkm_buffer_read_file(&b, btf_path, detail, detail_len);
	if (rc) {
		lkm_buffer_free(&b);
		return rc;
	}
	if (b.len < 24 || get16(b.data, 1) != 0xeb9f) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "not a BTF file");
		lkm_buffer_free(&b);
		return ENOEXEC;
	}
	hdr_len = btf_u32(b.data + 4);
	type_off = btf_u32(b.data + 8);
	type_len = btf_u32(b.data + 12);
	str_off = btf_u32(b.data + 16);
	str_len = btf_u32(b.data + 20);
	if ((size_t)hdr_len > b.len || (uint64_t)hdr_len + type_off + type_len > b.len ||
	    (uint64_t)hdr_len + str_off + str_len > b.len) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "BTF offsets are outside the file");
		lkm_buffer_free(&b);
		return ENOEXEC;
	}
	types = b.data + (size_t)hdr_len + type_off;
	strs = b.data + (size_t)hdr_len + str_off;

	pos = 0;
	while (pos + 12 <= (size_t)type_len) {
		uint32_t name_off = btf_u32(types + pos);
		uint32_t info = btf_u32(types + pos + 4);
		uint32_t type_size = btf_u32(types + pos + 8);
		int kind = (int)((info >> 24) & 0x1f);
		uint32_t vlen = info & 0xffff;
		size_t payload = btf_payload(kind, vlen);
		const char *name = NULL;

		if (payload > (size_t)type_len - pos - 12) {
			if (detail && detail_len)
				snprintf(detail, detail_len, "BTF type record is truncated");
			lkm_buffer_free(&b);
			return ENOEXEC;
		}
		if (name_off < str_len)
			name = (const char *)strs + name_off;

		if (kind == 4 && name && !strcmp(name, "module") && type_size > 0) {
			int got_name = 0, got_init = 0, got_exit = 0;
			size_t name_off_b = 0, init_off_b = 0, exit_off_b = 0;
			uint32_t m;

			for (m = 0; m < vlen; m++) {
				const unsigned char *mem = types + pos + 12 + (size_t)m * 12;
				uint32_t mno = btf_u32(mem);
				uint32_t moff = btf_u32(mem + 8) & 0xffffff;
				const char *mn;
				size_t byte;

				if (mno >= str_len)
					continue;
				mn = (const char *)strs + mno;
				if (moff % 8 != 0)
					continue;
				byte = moff / 8;
				if (!strcmp(mn, "name")) {
					name_off_b = byte;
					got_name = 1;
				} else if (!strcmp(mn, "init")) {
					init_off_b = byte;
					got_init = 1;
				} else if (!strcmp(mn, "exit")) {
					exit_off_b = byte;
					got_exit = 1;
				}
			}
			if (got_name && got_init) {
				layout->size = type_size;
				layout->name_off = name_off_b;
				layout->init_off = init_off_b;
				layout->have_exit = got_exit;
				layout->exit_off = got_exit ? exit_off_b : SIZE_MAX;
				lkm_buffer_free(&b);
				return 0;
			}
		}
		pos += 12 + payload;
	}
	if (detail && detail_len)
		snprintf(detail, detail_len, "no complete struct module in BTF");
	lkm_buffer_free(&b);
	return ENOENT;
}

static size_t align_up_size(size_t value, size_t align)
{
	return (value + align - 1) & ~(align - 1);
}

int lkm_adapt_module_layout(struct lkm_buffer *buf, const struct lkm_module_layout *layout,
			    const char *module_name, char *detail, size_t detail_len)
{
	struct lkm_elf_hdr hdr;
	struct lkm_elf_sec tm, rela, symtab, strtab;
	size_t name_len, init_off = SIZE_MAX, exit_off = SIZE_MAX;
	size_t align, off, need, i, count;
	unsigned char *fresh = NULL;
	int rc;

	if (detail && detail_len)
		detail[0] = '\0';
	if (!buf || !buf->data || !layout || !module_name || !*module_name) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "missing image or module name");
		return EINVAL;
	}
	name_len = strlen(module_name) + 1;
	if (layout->size == 0 || layout->name_off > layout->size ||
	    name_len > layout->size - layout->name_off || layout->init_off > layout->size - 8 ||
	    (layout->have_exit && layout->exit_off > layout->size - 8)) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "BTF module layout is unusable");
		return EINVAL;
	}

	rc = elf_parse_header(buf->data, buf->len, &hdr, detail, detail_len);
	if (rc)
		return rc;
	rc = elf_find_section(buf->data, buf->len, ".gnu.linkonce.this_module", &tm, detail,
			      detail_len);
	if (rc)
		return rc;
	/* The kernel rejects a NOBITS this_module outright; there would be no
	 * section contents to adapt or to point relocations into. */
	if (tm.type == LKM_SHT_NOBITS) {
		if (detail && detail_len)
			snprintf(detail, detail_len,
				 ".gnu.linkonce.this_module has no file contents");
		return ENOEXEC;
	}
	rc = elf_find_section(buf->data, buf->len, ".rela.gnu.linkonce.this_module", &rela, detail,
			      detail_len);
	if (rc)
		return rc;
	if (rela.type != 4 /* SHT_RELA */ || rela.entsize < 24 || rela.size % 24 != 0) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "unusable this_module relocations");
		return ENOEXEC;
	}
	rc =
	    elf_section_by_index(buf->data, buf->len, &hdr, rela.link, &symtab, detail, detail_len);
	if (rc)
		return rc;
	rc = elf_section_by_index(buf->data, buf->len, &hdr, symtab.link, &strtab, detail,
				  detail_len);
	if (rc)
		return rc;
	if (symtab.entsize < 24 || strtab.size == 0) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "unusable symbol/string table");
		return ENOEXEC;
	}

	count = rela.size / 24;
	for (i = 0; i < count; i++) {
		const unsigned char *re = buf->data + rela.off + i * 24;
		uint64_t r_offset = get64(re, hdr.little_endian);
		uint64_t r_info = get64(re + 8, hdr.little_endian);
		size_t sym = (size_t)(r_info >> 32);
		uint32_t st_name;
		const char *sym_name;

		if (sym == 0 || sym * 24 + 24 > symtab.size)
			continue;
		st_name = get32(buf->data + symtab.off + sym * 24, hdr.little_endian);
		if (st_name >= strtab.size)
			continue;
		sym_name = (const char *)buf->data + strtab.off + st_name;
		if (strnlen(sym_name, strtab.size - st_name) == strtab.size - st_name)
			continue;
		if (!strcmp(sym_name, "init_module"))
			init_off = (size_t)r_offset;
		else if (!strcmp(sym_name, "cleanup_module"))
			exit_off = (size_t)r_offset;
	}

	if (init_off == SIZE_MAX || (layout->have_exit && exit_off == SIZE_MAX)) {
		if (detail && detail_len)
			snprintf(detail, detail_len,
				 "module lacks the init/exit relocations this "
				 "kernel needs");
		return ENOENT;
	}

	if (tm.size == layout->size && init_off == layout->init_off &&
	    (!layout->have_exit || exit_off == layout->exit_off) &&
	    tm.size >= layout->name_off + name_len &&
	    !memcmp(buf->data + tm.off + layout->name_off, module_name, name_len))
		return 0;

	align = tm.align ? tm.align : 8;
	if ((align & (align - 1)) != 0) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "invalid this_module alignment %zu", align);
		return ENOEXEC;
	}
	if (buf->len > SIZE_MAX - align || buf->len + align - 1 < buf->len) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "image size overflow");
		return EOVERFLOW;
	}
	off = align_up_size(buf->len, align);
	if (off > SIZE_MAX - layout->size) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "image size overflow");
		return EOVERFLOW;
	}
	need = off + layout->size;

	fresh = calloc(1, layout->size);
	if (!fresh) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "out of memory rebuilding this_module");
		return ENOMEM;
	}
	memcpy(fresh + layout->name_off, module_name, name_len);

	rc = lkm_buffer_reserve(buf, need);
	if (rc) {
		if (detail && detail_len)
			snprintf(detail, detail_len, "out of memory growing the image");
		free(fresh);
		return rc;
	}
	if (off > buf->len)
		memset(buf->data + buf->len, 0, off - buf->len);
	memcpy(buf->data + off, fresh, layout->size);
	buf->len = need;
	put64(buf->data + tm.hdr_off + 24, off, hdr.little_endian);
	put64(buf->data + tm.hdr_off + 32, layout->size, hdr.little_endian);

	for (i = 0; i < count; i++) {
		unsigned char *re = buf->data + rela.off + i * 24;
		uint64_t r_info = get64(re + 8, hdr.little_endian);
		size_t sym = (size_t)(r_info >> 32);
		uint32_t st_name;
		const char *sym_name;

		if (sym == 0 || sym * 24 + 24 > symtab.size)
			continue;
		st_name = get32(buf->data + symtab.off + sym * 24, hdr.little_endian);
		if (st_name >= strtab.size)
			continue;
		sym_name = (const char *)buf->data + strtab.off + st_name;
		if (strnlen(sym_name, strtab.size - st_name) == strtab.size - st_name)
			continue;
		if (!strcmp(sym_name, "init_module"))
			put64(re, layout->init_off, hdr.little_endian);
		else if (!strcmp(sym_name, "cleanup_module") && layout->have_exit)
			put64(re, layout->exit_off, hdr.little_endian);
	}

	free(fresh);
	return 0;
}

/* ---- load driver -------------------------------------------------------- */

int lkm_insmod_exec(struct lkm_buffer *buf, const char *params, const struct lkm_insmod_ops *ops,
		    struct lkm_insmod_result *result)
{
	char log[LKM_INSMOD_LOG_MAX];
	int n, rc;

	if (!buf || !buf->data || !ops || !ops->load || !result)
		return EINVAL;
	memset(result, 0, sizeof(*result));
	if (!params)
		params = "";

	result->first_errno = ops->load(ops->ctx, buf->data, buf->len, params);
	result->attempts = 1;
	if (result->first_errno == 0) {
		result->err = 0;
		return 0;
	}
	if (result->first_errno != ENOEXEC) {
		result->err = result->first_errno;
		snprintf(result->detail, sizeof(result->detail),
			 "init_module failed with %s; no vermagic retry is "
			 "attempted",
			 strerror(result->err));
		return result->err;
	}

	/* ENOEXEC: only the records written after the pre-load drain matter. */
	if (!ops->read_log) {
		result->err = ENOEXEC;
		snprintf(result->detail, sizeof(result->detail),
			 "the kernel rejected the image and no kernel-log reader "
			 "is available; refusing to retry blindly");
		return ENOEXEC;
	}
	n = ops->read_log(ops->ctx, log, sizeof(log));
	if (n < 0) {
		result->err = ENOEXEC;
		snprintf(result->detail, sizeof(result->detail),
			 "the kernel rejected the image and the kernel log could "
			 "not be read (%s); refusing to retry blindly",
			 strerror(-n));
		return ENOEXEC;
	}
	if ((size_t)n >= sizeof(log))
		n = (int)sizeof(log) - 1;
	log[n] = '\0';

	rc = lkm_extract_required_vermagic(log, (size_t)n, result->required,
					   sizeof(result->required));
	if (rc) {
		result->err = ENOEXEC;
		snprintf(result->detail, sizeof(result->detail),
			 "the kernel rejected the image but its log reported no "
			 "complete \"version magic ... should be ...\" record; "
			 "refusing to retry blindly");
		return ENOEXEC;
	}

	rc = lkm_rewrite_vermagic(buf, result->required, result->detail, sizeof(result->detail));
	if (rc) {
		char why[LKM_INSMOD_DETAIL_MAX];

		snprintf(why, sizeof(why), "%s", result->detail);
		result->err = ENOEXEC;
		snprintf(result->detail, sizeof(result->detail),
			 "the kernel rejected the image; rewriting its vermagic "
			 "failed: %.160s",
			 why);
		return ENOEXEC;
	}

	result->rewritten = 1;
	result->attempts = 2;
	rc = ops->load(ops->ctx, buf->data, buf->len, params);
	if (rc == 0) {
		result->err = 0;
		return 0;
	}
	result->err = rc;
	snprintf(result->detail, sizeof(result->detail),
		 "init_module failed again after rewriting vermagic "
		 "(retried exactly once): %.160s",
		 strerror(rc));
	return rc;
}

/* ---- unsafe-load confirmation ------------------------------------------ */

static void strip_newline(char *line)
{
	size_t n = strlen(line);

	while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
}

int lkm_confirm_unsafe_load(FILE *in, FILE *out)
{
	char first[256], second[256];

	if (!in || !out)
		return EINVAL;
	fputs("This module's struct module layout cannot be adapted to this "
	      "kernel.\n"
	      "If the kernel accepts it, it may never be possible to unload "
	      "it.\n"
	      "To proceed anyway, type the following line exactly:\n"
	      "  " LKM_UNSAFE_CONFIRM_SENTENCE "\n"
	      "confirmation 1/2: ",
	      out);
	fflush(out);
	if (!fgets(first, sizeof(first), in)) {
		fputs("\naborted: no confirmation input\n", out);
		return ECANCELED;
	}
	strip_newline(first);
	if (strcmp(first, LKM_UNSAFE_CONFIRM_SENTENCE) != 0) {
		fputs("\naborted: the line did not match exactly\n", out);
		return ECANCELED;
	}

	fputs("type the same line a second time\nconfirmation 2/2: ", out);
	fflush(out);
	if (!fgets(second, sizeof(second), in)) {
		fputs("\naborted: no second confirmation input\n", out);
		return ECANCELED;
	}
	strip_newline(second);
	if (strcmp(second, LKM_UNSAFE_CONFIRM_SENTENCE) != 0) {
		fputs("\naborted: the second line did not match exactly\n", out);
		return ECANCELED;
	}

	fputs("\nconfirmed.\n", out);
	return 0;
}
