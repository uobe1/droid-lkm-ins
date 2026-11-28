/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests for the insmod core: path canonicalization, kernel-log vermagic
 * extraction, .modinfo rewrite, and the exactly-one retry driver.
 *
 * No kernel is needed.  Modules are synthesized in memory as ELF64
 * relocatable objects with a .modinfo section, and the load callback is a fake
 * that records how many times it was called and what vermagic it was handed.
 *
 * Build/run: make test  (or make build/lkm_insmod_test && ./build/lkm_insmod_test)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lkm_insmod.h"

static int checks;
static int failures;

#define CHECK(cond, ...)                                                      \
	do {                                                                  \
		checks++;                                                     \
		if (!(cond)) {                                                \
			failures++;                                           \
			fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);  \
			fprintf(stderr, __VA_ARGS__);                         \
			fputc('\n', stderr);                                  \
		}                                                             \
	} while (0)

/* ---- little-endian writers and readers used by the ELF fixture -------- */

static void w16(unsigned char *p, unsigned v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void w32(unsigned char *p, unsigned long v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
	p[2] = (unsigned char)((v >> 16) & 0xff);
	p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void w64(unsigned char *p, unsigned long long v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static unsigned t16(const unsigned char *p)
{
	return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned long t32(const unsigned char *p)
{
	return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
	       ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static unsigned long long t64(const unsigned char *p)
{
	unsigned long long v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

/* ---- synthetic ELF64 module -------------------------------------------- */

static const char k_shstr[] = "\0.modinfo\0.shstrtab\0";

static size_t put_entry(unsigned char *buf, size_t cap, size_t off,
			const char *s)
{
	size_t n = strlen(s);

	if (off + n + 1 > cap)
		return 0;
	memcpy(buf + off, s, n);
	buf[off + n] = '\0';
	return off + n + 1;
}

/*
 * Lay out: ELF header | .modinfo | .shstrtab | (pad) | section headers.
 * Returns the image length, or 0 when `cap` is too small.
 */
static size_t build_module(unsigned char *buf, size_t cap,
			   const unsigned char *modinfo, size_t modinfo_len,
			   int include_modinfo, size_t modinfo_align)
{
	size_t shstr_len = sizeof(k_shstr) - 1;
	size_t modinfo_off = 64;
	size_t shstr_off = include_modinfo ? modinfo_off + modinfo_len
					   : modinfo_off;
	size_t data_end = shstr_off + shstr_len;
	size_t shoff = (data_end + 7) & ~(size_t)7;
	unsigned shnum = include_modinfo ? 3 : 2;
	size_t total = shoff + (size_t)shnum * 64;
	unsigned char *sh;

	if (total > cap)
		return 0;
	memset(buf, 0, total);

	buf[0] = 0x7f;
	buf[1] = 'E';
	buf[2] = 'L';
	buf[3] = 'F';
	buf[4] = 2; /* ELFCLASS64 */
	buf[5] = 1; /* ELFDATA2LSB */
	buf[6] = 1; /* EV_CURRENT */
	w16(buf + 16, 1);         /* e_type = ET_REL */
	w16(buf + 18, 183);       /* e_machine = EM_AARCH64 */
	w32(buf + 20, 1);         /* e_version */
	w64(buf + 40, shoff);     /* e_shoff */
	w16(buf + 52, 64);        /* e_ehsize */
	w16(buf + 58, 64);        /* e_shentsize */
	w16(buf + 60, shnum);     /* e_shnum */
	w16(buf + 62, include_modinfo ? 2 : 1); /* e_shstrndx */

	if (include_modinfo)
		memcpy(buf + modinfo_off, modinfo, modinfo_len);
	memcpy(buf + shstr_off, k_shstr, shstr_len);

	/* Section 0: SHT_NULL, all zero. */
	sh = buf + shoff;
	if (include_modinfo) {
		sh += 64;
		w32(sh + 0, 1);  /* sh_name -> ".modinfo" */
		w32(sh + 4, 1);  /* SHT_PROGBITS */
		w64(sh + 8, 2);  /* SHF_ALLOC */
		w64(sh + 24, modinfo_off);
		w64(sh + 32, modinfo_len);
		w64(sh + 48, modinfo_align);
	}
	sh = buf + shoff + ((size_t)shnum - 1) * 64;
	w32(sh + 0, 10);  /* sh_name -> ".shstrtab" */
	w32(sh + 4, 3);   /* SHT_STRTAB */
	w64(sh + 24, shstr_off);
	w64(sh + 32, shstr_len);
	w64(sh + 48, 1);

	return total;
}

static uint64_t section_field(const unsigned char *buf, const char *wanted,
			      int field)
{
	unsigned long long shoff = t64(buf + 40);
	unsigned shentsize = t16(buf + 58);
	unsigned shnum = t16(buf + 60);
	unsigned shstrndx = t16(buf + 62);
	unsigned long long stroff = t64(buf + shoff + shstrndx * shentsize + 24);
	unsigned i;

	for (i = 0; i < shnum; i++) {
		unsigned char *sh = (unsigned char *)buf + shoff +
				    (size_t)i * shentsize;
		const char *name = (const char *)buf + stroff + t32(sh + 0);

		if (!strcmp(name, wanted))
			return t64(sh + field);
	}
	return 0;
}

static uint64_t modinfo_offset(const unsigned char *buf)
{
	return section_field(buf, ".modinfo", 24);
}

static uint64_t modinfo_size(const unsigned char *buf)
{
	return section_field(buf, ".modinfo", 32);
}

/* Count "key=" entries inside the .modinfo section (not the whole file). */
static int modinfo_count(const unsigned char *buf, size_t len,
			 const char *key)
{
	uint64_t off = modinfo_offset(buf);
	uint64_t size = modinfo_size(buf);
	const unsigned char *p;
	size_t left, key_len = strlen(key);
	int count = 0;

	if (off == 0 || off + size > len)
		return -1;
	p = buf + off;
	left = (size_t)size;
	while (left > 0) {
		size_t n = strnlen((const char *)p, left);

		if (n >= key_len + 1 && !memcmp(p, key, key_len) &&
		    p[key_len] == '=')
			count++;
		if (n == left)
			break;
		p += n + 1;
		left -= n + 1;
	}
	return count;
}

static const char k_foreign[] = "6.1.0-foreign SMP preempt mod_unload";
static const char k_required[] =
	"6.12.30-android16-5 SMP preempt mod_unload modversions aarch64";

static size_t build_test_module(unsigned char *buf, size_t cap,
				int include_vermagic, int include_modinfo,
				size_t align)
{
	unsigned char modinfo[512];
	size_t mlen = 0;

	mlen = put_entry(modinfo, sizeof(modinfo), mlen, "name=testmod");
	mlen = put_entry(modinfo, sizeof(modinfo), mlen, "license=GPL");
	if (include_vermagic) {
		char entry[LKM_INSMOD_VERMAGIC_MAX + 16];

		snprintf(entry, sizeof(entry), "vermagic=%s", k_foreign);
		mlen = put_entry(modinfo, sizeof(modinfo), mlen, entry);
	}
	return build_module(buf, cap, modinfo, mlen, include_modinfo, align);
}

/* Own a copy of an image with cap == len, so a rewrite must grow it. */
static void own_image(struct lkm_buffer *b, const unsigned char *src, size_t len)
{
	lkm_buffer_init(b);
	b->data = malloc(len);
	b->len = len;
	b->cap = len;
	if (b->data)
		memcpy(b->data, src, len);
}

/* ---- 0. kernel BTF layout and .this_module adaptation ------------------- */

static unsigned str_off(const char *strs, size_t len, const char *s)
{
	size_t n = strlen(s);
	size_t i;

	for (i = 0; i + n < len; i++)
		if (!memcmp(strs + i, s, n) && strs[i + n] == '\0')
			return (unsigned)i;
	return 0;
}

static int write_btf_file(const char *path, size_t module_size,
			  size_t name_off, size_t init_off, size_t exit_off)
{
	static const char strs[] = "\0module\0name\0init\0exit\0arch\0";
	unsigned char b[512];
	size_t slen = sizeof(strs) - 1;
	size_t type_len, pos;
	struct {
		const char *name;
		size_t byte_off;
	} mem[4] = {
		{ "name", name_off },
		{ "init", init_off },
		{ "exit", exit_off },
		{ "arch", 952 },
	};
	FILE *f;
	int i;

	memset(b, 0, sizeof(b));
	w16(b, 0xeb9f);
	b[2] = 1;
	w32(b + 4, 24); /* hdr_len */
	pos = 24;
	w32(b + pos, str_off(strs, slen, "module"));
	w32(b + pos + 4, (4u << 24) | 4u); /* STRUCT, 4 members */
	w32(b + pos + 8, (unsigned long)module_size);
	pos += 12;
	for (i = 0; i < 4; i++) {
		w32(b + pos, str_off(strs, slen, mem[i].name));
		w32(b + pos + 4, 0);
		w32(b + pos + 8, (unsigned long)(mem[i].byte_off * 8));
		pos += 12;
	}
	type_len = pos - 24;
	w32(b + 8, 0);   /* type_off */
	w32(b + 12, (unsigned long)type_len);
	w32(b + 16, (unsigned long)type_len); /* str_off */
	w32(b + 20, slen);
	memcpy(b + 24 + type_len, strs, slen);

	f = fopen(path, "wb");
	if (!f)
		return -1;
	if (fwrite(b, 1, 24 + type_len + slen, f) !=
	    24 + type_len + slen) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* Minimal ELF64 relocatable module carrying this_module + rela + symtab. */
static size_t build_abi_module(unsigned char *buf, size_t cap,
			       size_t tm_size, size_t name_off,
			       size_t init_reloc, size_t exit_reloc,
			       int with_rela)
{
	static const char shstr[] =
		"\0.text\0.gnu.linkonce.this_module\0"
		".rela.gnu.linkonce.this_module\0.symtab\0.strtab\0.shstrtab\0";
	static const char strtab[] = "\0init_module\0cleanup_module\0";
	size_t shstr_len = sizeof(shstr) - 1;
	size_t strtab_len = sizeof(strtab) - 1;
	size_t text_off = 64, tm_off = 128;
	size_t rela_off = (tm_off + tm_size + 7) & ~(size_t)7;
	size_t rela_size = with_rela ? 48 : 0;
	size_t sym_off = (rela_off + rela_size + 7) & ~(size_t)7;
	size_t str_off_b = sym_off + 72;
	size_t shstr_off = str_off_b + strtab_len;
	size_t shoff = (shstr_off + shstr_len + 7) & ~(size_t)7;
	size_t total = shoff + 7 * 64;
	unsigned char *sh;
	const char *name = "tmp_lkm";

	if (total > cap)
		return 0;
	memset(buf, 0, total);

	buf[0] = 0x7f;
	buf[1] = 'E';
	buf[2] = 'L';
	buf[3] = 'F';
	buf[4] = 2;
	buf[5] = 1;
	buf[6] = 1;
	w16(buf + 16, 1);          /* ET_REL */
	w16(buf + 18, 183);        /* AARCH64 */
	w32(buf + 20, 1);
	w64(buf + 40, shoff);
	w16(buf + 52, 64);
	w16(buf + 58, 64);
	w16(buf + 60, 7);
	w16(buf + 62, 6);          /* shstrtab index */

	buf[text_off] = 0xc0;
	buf[text_off + 1] = 0x03;
	buf[text_off + 2] = 0xd6;
	buf[text_off + 4] = 0xc0;
	buf[text_off + 5] = 0x03;
	buf[text_off + 6] = 0xd6;
	if (tm_size > name_off)
		memcpy(buf + tm_off + name_off, name, strlen(name) + 1);

	if (with_rela) {
		/* init_module: symbol 1, cleanup_module: symbol 2 */
		w64(buf + rela_off, init_reloc);
		w64(buf + rela_off + 8, ((uint64_t)1 << 32) | 257);
		w64(buf + rela_off + 24, exit_reloc);
		w64(buf + rela_off + 32, ((uint64_t)2 << 32) | 257);
	}

	/* symtab: null, init_module@.text+0, cleanup_module@.text+4 */
	w32(buf + sym_off + 24, 1);        /* st_name "init_module" */
	buf[sym_off + 28] = 0x12;          /* GLOBAL FUNC */
	w16(buf + sym_off + 30, 1);        /* .text */
	w64(buf + sym_off + 32, 0);
	w64(buf + sym_off + 40, 4);
	w32(buf + sym_off + 48, 13);       /* "cleanup_module" */
	buf[sym_off + 52] = 0x12;
	w16(buf + sym_off + 54, 1);
	w64(buf + sym_off + 56, 4);
	w64(buf + sym_off + 64, 4);

	memcpy(buf + str_off_b, strtab, strtab_len);
	memcpy(buf + shstr_off, shstr, shstr_len);

	sh = buf + shoff;
	/* s1 .text */
	w32(sh + 64, 1);
	w32(sh + 68, 1);
	w64(sh + 72, 6);
	w64(sh + 64 + 24, text_off);
	w64(sh + 64 + 32, 8);
	w64(sh + 64 + 48, 8);
	/* s2 .gnu.linkonce.this_module */
	w32(sh + 128, str_off(shstr, shstr_len, ".gnu.linkonce.this_module"));
	w32(sh + 132, 1);
	w64(sh + 136, 3);
	w64(sh + 128 + 24, tm_off);
	w64(sh + 128 + 32, tm_size);
	w64(sh + 128 + 48, 8);
	/* s3 .rela... */
	w32(sh + 192, str_off(shstr, shstr_len, ".rela.gnu.linkonce.this_module"));
	w32(sh + 196, 4);
	w64(sh + 192 + 24, rela_off);
	w64(sh + 192 + 32, rela_size);
	w32(sh + 192 + 40, 4);   /* link: symtab */
	w32(sh + 192 + 44, 2);   /* info: this_module */
	w64(sh + 192 + 48, 8);
	w64(sh + 192 + 56, 24);
	/* s4 .symtab */
	w32(sh + 256, str_off(shstr, shstr_len, ".symtab"));
	w32(sh + 260, 2);
	w64(sh + 256 + 24, sym_off);
	w64(sh + 256 + 32, 72);
	w32(sh + 256 + 40, 5);   /* link: strtab */
	w32(sh + 256 + 44, 1);
	w64(sh + 256 + 48, 8);
	w64(sh + 256 + 56, 24);
	/* s5 .strtab */
	w32(sh + 320, str_off(shstr, shstr_len, ".strtab"));
	w32(sh + 324, 3);
	w64(sh + 320 + 24, str_off_b);
	w64(sh + 320 + 32, strtab_len);
	w64(sh + 320 + 48, 1);
	/* s6 .shstrtab */
	w32(sh + 384, str_off(shstr, shstr_len, ".shstrtab"));
	w32(sh + 388, 3);
	w64(sh + 384 + 24, shstr_off);
	w64(sh + 384 + 32, shstr_len);
	w64(sh + 384 + 48, 1);

	return total;
}

static uint64_t abi_section_field(const unsigned char *buf, const char *wanted,
				  int field)
{
	unsigned long long shoff = t64(buf + 40);
	unsigned shentsize = t16(buf + 58);
	unsigned shnum = t16(buf + 60);
	unsigned shstrndx = t16(buf + 62);
	unsigned long long stroff = t64(buf + shoff + shstrndx * shentsize + 24);
	unsigned i;

	for (i = 0; i < shnum; i++) {
		unsigned char *sh = (unsigned char *)buf + shoff +
				    (size_t)i * shentsize;
		const char *name = (const char *)buf + stroff + t32(sh);

		if (!strcmp(name, wanted))
			return t64(sh + field);
	}
	return 0;
}

static void test_abi_layout(void)
{
	char path[] = "/tmp/lkm-ins-btf-XXXXXX";
	struct lkm_module_layout lay;
	struct lkm_buffer b;
	unsigned char raw[4096];
	char detail[LKM_INSMOD_DETAIL_MAX];
	size_t total;
	int fd;

	fd = mkstemp(path);
	CHECK(fd >= 0, "mkstemp btf: %s", strerror(errno));
	if (fd < 0)
		return;
	close(fd);
	CHECK(write_btf_file(path, 1600, 192, 392, 1528) == 0,
	      "write synthetic BTF failed");
	CHECK(lkm_btf_module_layout(path, &lay, detail, sizeof(detail)) == 0,
	      "BTF parse failed: %s", detail);
	CHECK(lay.size == 1600 && lay.name_off == 192 &&
		      lay.init_off == 392 && lay.have_exit &&
		      lay.exit_off == 1528,
	      "BTF layout wrong: size=%zu name=%zu init=%zu exit=%zu",
	      lay.size, lay.name_off, lay.init_off, lay.exit_off);
	unlink(path);

	{
		struct lkm_module_layout missing;

		CHECK(lkm_btf_module_layout("/tmp/no-such-btf-file", &missing,
					    detail, sizeof(detail)) == ENOENT,
		      "missing BTF did not return ENOENT");
	}

	/* Wrong exit offset: must be moved to the kernel's 1528. */
	total = build_abi_module(raw, sizeof(raw), 1600, 192, 392, 1504, 1);
	CHECK(total > 0, "abi module fixture failed");
	if (total > 0) {
		own_image(&b, raw, total);
		detail[0] = '\0';
		CHECK(lkm_adapt_module_layout(&b, &lay, "tmp_lkm", detail,
					      sizeof(detail)) == 0,
		      "adapt failed: %s", detail);
		CHECK(b.len > total, "adapted image did not grow");
		CHECK(abi_section_field(b.data, ".gnu.linkonce.this_module", 32) ==
			      1600,
		      "this_module sh_size not 1600");
		{
			uint64_t roff = abi_section_field(
				b.data, ".rela.gnu.linkonce.this_module", 24);
			uint64_t rsize = abi_section_field(
				b.data, ".rela.gnu.linkonce.this_module", 32);

			CHECK(rsize == 48, "rela size %llu",
			      (unsigned long long)rsize);
			CHECK(t64(b.data + roff) == 392,
			      "init reloc %llu",
			      (unsigned long long)t64(b.data + roff));
			CHECK(t64(b.data + roff + 24) == 1528,
			      "exit reloc %llu",
			      (unsigned long long)t64(b.data + roff + 24));
		}
		{
			uint64_t tmoff = abi_section_field(
				b.data, ".gnu.linkonce.this_module", 24);

			CHECK(!strcmp((const char *)b.data + tmoff + 192,
				      "tmp_lkm"),
			      "name not at kernel offset");
		}
		lkm_buffer_free(&b);
	}

	/* Already matching: no change. */
	total = build_abi_module(raw, sizeof(raw), 1600, 192, 392, 1528, 1);
	if (total > 0) {
		own_image(&b, raw, total);
		detail[0] = '\0';
		CHECK(lkm_adapt_module_layout(&b, &lay, "tmp_lkm", detail,
					      sizeof(detail)) == 0,
		      "no-op adapt failed: %s", detail);
		CHECK(b.len == total && !memcmp(b.data, raw, total),
		      "matching layout was modified");
		lkm_buffer_free(&b);
	}

	/* Older/smaller this_module: must grow to the kernel's size. */
	total = build_abi_module(raw, sizeof(raw), 1200, 192, 392, 1504, 1);
	if (total > 0) {
		own_image(&b, raw, total);
		detail[0] = '\0';
		CHECK(lkm_adapt_module_layout(&b, &lay, "tmp_lkm", detail,
					      sizeof(detail)) == 0,
		      "grow adapt failed: %s", detail);
		CHECK(abi_section_field(b.data, ".gnu.linkonce.this_module", 32) ==
			      1600,
		      "grown this_module sh_size wrong");
		lkm_buffer_free(&b);
	}

	/* No relocations: fail closed, image untouched. */
	total = build_abi_module(raw, sizeof(raw), 1600, 192, 392, 1504, 0);
	if (total > 0) {
		unsigned char snap[4096];

		memcpy(snap, raw, total);
		own_image(&b, raw, total);
		detail[0] = '\0';
		CHECK(lkm_adapt_module_layout(&b, &lay, "tmp_lkm", detail,
					      sizeof(detail)) == ENOENT,
		      "missing rela did not return ENOENT");
		CHECK(b.len == total && !memcmp(b.data, snap, total),
		      "failed adapt modified the image");
		lkm_buffer_free(&b);
	}
}

/*
 * A real module's .bss is SHT_NOBITS: it occupies no file bytes, and the
 * kernel skips it when validating section contents.  A large .bss placed
 * before .gnu.linkonce.this_module must not be mistaken for a truncated
 * image; the module linker script produces that order.
 */
static void test_abi_nobits(void)
{
	unsigned char raw[8192];
	struct lkm_buffer b;
	struct lkm_module_layout lay = { 1600, 24, 392, 1528, 1 };
	char detail[LKM_INSMOD_DETAIL_MAX];
	size_t total, table_off, new_total;
	unsigned char *tab;

	total = build_abi_module(raw, sizeof(raw), 1600, 24, 392, 1528, 1);
	CHECK(total > 0, "nobits fixture failed");
	if (!total)
		return;

	/* Insert a legal SHT_NOBITS section before .this_module: section 0 is
	 * NULL, section 1 is the .bss, and the six existing headers move to
	 * indices 2..7. */
	table_off = total + 64;
	new_total = table_off + 8 * 64;
	CHECK(new_total <= sizeof(raw), "nobits fixture does not fit");
	if (new_total > sizeof(raw))
		return;
	memset(raw + table_off, 0, 8 * 64);
	memcpy(raw + table_off + 2 * 64, raw + (size_t)t64(raw + 40) + 64,
	       6 * 64);
	tab = raw + table_off + 64;
	tab[0] = 1;              /* sh_name: any valid offset */
	tab[4] = 8;              /* SHT_NOBITS */
	tab[8] = 3;              /* SHF_ALLOC | SHF_WRITE */
	w64(tab + 24, 2000);     /* sh_offset inside the image */
	w64(tab + 32, 1u << 20); /* sh_size: 1 MiB, past EOF */
	w64(raw + 40, table_off); /* e_shoff */
	w16(raw + 60, 8);         /* e_shnum */
	w16(raw + 62, 7);         /* e_shstrndx */

	/* Moving the headers one slot up changed the indices their sh_link /
	 * sh_info fields refer to; fix them up as a real linker would. */
	w32(raw + table_off + 4 * 64 + 40, 5); /* rela.sh_link -> symtab */
	w32(raw + table_off + 4 * 64 + 44, 3); /* rela.sh_info -> this_module */
	w32(raw + table_off + 5 * 64 + 40, 6); /* symtab.sh_link -> strtab */

	own_image(&b, raw, new_total);
	detail[0] = '\0';
	CHECK(lkm_adapt_module_layout(&b, &lay, "tmp_lkm", detail,
				      sizeof(detail)) == 0,
	      "legal SHT_NOBITS .bss was rejected: %s", detail);
	CHECK(abi_section_field(b.data, ".gnu.linkonce.this_module", 32) ==
		      1600,
	      "adapted this_module size wrong with .bss present");
	lkm_buffer_free(&b);

	/* A NOBITS .this_module itself is still refused: there are no file
	 * contents to adapt, and the kernel rejects it too. */
	total = build_abi_module(raw, sizeof(raw), 1600, 24, 392, 1528, 1);
	CHECK(total > 0, "nobits this_module fixture failed");
	if (!total)
		return;
	w32(raw + (size_t)t64(raw + 40) + 2 * 64 + 4, 8); /* SHT_NOBITS */
	own_image(&b, raw, total);
	detail[0] = '\0';
	CHECK(lkm_adapt_module_layout(&b, &lay, "tmp_lkm", detail,
				      sizeof(detail)) == ENOEXEC,
	      "NOBITS .this_module was accepted: %s", detail);
	lkm_buffer_free(&b);
}

/* ---- 0b. unsafe-load confirmation --------------------------------------- */

static FILE *stream_with(const char *text)
{
	FILE *f = tmpfile();

	if (!f)
		return NULL;
	if (text)
		fputs(text, f);
	rewind(f);
	return f;
}

static void expect_confirm(const char *input, int want, const char *desc)
{
	FILE *in = stream_with(input);
	FILE *out = tmpfile();
	int rc;

	CHECK(in != NULL && out != NULL, "%s: tmpfile failed", desc);
	if (!in || !out) {
		if (in)
			fclose(in);
		if (out)
			fclose(out);
		return;
	}
	rc = lkm_confirm_unsafe_load(in, out);
	CHECK(rc == want, "%s: rc=%d want %d", desc, rc, want);
	fclose(in);
	fclose(out);
}

static void test_confirm(void)
{
	expect_confirm(LKM_UNSAFE_CONFIRM_SENTENCE "\n"
		       LKM_UNSAFE_CONFIRM_SENTENCE "\n",
		       0, "exact sentence twice");
	expect_confirm("yes\n" LKM_UNSAFE_CONFIRM_SENTENCE "\n", ECANCELED,
		       "wrong first line");
	expect_confirm(LKM_UNSAFE_CONFIRM_SENTENCE "\nnope\n", ECANCELED,
		       "wrong second line");
	expect_confirm("", ECANCELED, "EOF before confirmation");
	expect_confirm(LKM_UNSAFE_CONFIRM_SENTENCE " \n"
		       LKM_UNSAFE_CONFIRM_SENTENCE "\n",
		       ECANCELED, "trailing space is not exact");
	CHECK(lkm_confirm_unsafe_load(NULL, NULL) == EINVAL,
	      "NULL streams did not return EINVAL");
}

/* ---- 1. path canonicalization ------------------------------------------ */

static void test_paths(void)
{
	char root[] = "/tmp/lkm-ins-test-XXXXXX";
	char sub[512], dir[512], file[512], link[512], dotted[512];
	char out[512], small[8];
	char cwd[PATH_MAX];
	int have_cwd;

	CHECK(mkdtemp(root) != NULL, "mkdtemp failed: %s", strerror(errno));
	if (!root[0])
		return;

	snprintf(sub, sizeof(sub), "%s/sub", root);
	snprintf(dir, sizeof(dir), "%s/sub/dir", root);
	snprintf(file, sizeof(file), "%s/sub/dir/mod.ko", root);
	snprintf(link, sizeof(link), "%s/link.ko", root);
	snprintf(dotted, sizeof(dotted), "%s/sub/../sub/./dir/mod.ko", root);

	CHECK(mkdir(sub, 0700) == 0, "mkdir sub: %s", strerror(errno));
	CHECK(mkdir(dir, 0700) == 0, "mkdir dir: %s", strerror(errno));
	{
		FILE *f = fopen(file, "wb");

		CHECK(f != NULL, "create module file: %s", strerror(errno));
		if (f)
			fclose(f);
	}
	CHECK(symlink(file, link) == 0, "symlink: %s", strerror(errno));

	CHECK(lkm_canonicalize_path(file, out, sizeof(out)) == 0 &&
		      !strcmp(out, file),
	      "absolute path not canonical: %s", out);
	CHECK(lkm_canonicalize_path(dotted, out, sizeof(out)) == 0 &&
		      !strcmp(out, file),
	      "dotted path not canonical: %s", out);
	CHECK(lkm_canonicalize_path(link, out, sizeof(out)) == 0 &&
		      !strcmp(out, file),
	      "symlink not resolved: %s", out);
	CHECK(lkm_canonicalize_path(sub, out, sizeof(out)) == 0 &&
		      !strcmp(out, sub),
	      "directory path not canonical: %s", out);

	have_cwd = getcwd(cwd, sizeof(cwd)) != NULL;
	if (have_cwd) {
		CHECK(chdir(root) == 0, "chdir root: %s", strerror(errno));
		CHECK(lkm_canonicalize_path("sub/./dir/../dir/mod.ko", out,
					    sizeof(out)) == 0 &&
			      !strcmp(out, file),
		      "relative path not canonical: %s", out);
		CHECK(chdir(cwd) == 0, "chdir back: %s", strerror(errno));
	} else {
		fprintf(stderr, "skip: relative-path case (no cwd)\n");
	}

	CHECK(lkm_canonicalize_path("/tmp/definitely-not-there-lkmins", out,
				    sizeof(out)) == ENOENT,
	      "missing path did not return ENOENT");
	CHECK(lkm_canonicalize_path("", out, sizeof(out)) == EINVAL,
	      "empty path did not return EINVAL");
	CHECK(lkm_canonicalize_path(NULL, out, sizeof(out)) == EINVAL,
	      "NULL path did not return EINVAL");
	CHECK(lkm_canonicalize_path(file, small, sizeof(small)) ==
		      ENAMETOOLONG,
	      "small output buffer did not return ENAMETOOLONG");

	unlink(link);
	unlink(file);
	rmdir(dir);
	rmdir(sub);
	rmdir(root);
}

/* ---- 2. required-vermagic extraction from the kernel log --------------- */

static void test_extract(void)
{
	char out[LKM_INSMOD_VERMAGIC_MAX];
	char tiny[8];
	const char *log_header =
		"6,100,1,-;testmod: version magic '6.1.0-foreign SMP preempt "
		"mod_unload' should be '6.12.30-android16-5 SMP preempt "
		"mod_unload modversions aarch64'\n";
	const char *log_plain =
		"version magic '6.1.0-foreign SMP preempt mod_unload' should be "
		"'6.12.30-android16-5 SMP preempt mod_unload modversions aarch64'\n";
	const char *log_two =
		"6,1,1,-;oldmod: version magic 'x' should be 'OLD-REQUIRED'\n"
		"6,2,2,-;testmod: version magic 'y' should be 'NEW-REQUIRED'\n";
	const char *log_decoy =
		"6,3,3,-;usb 1-1: new high-speed USB device\n"
		"6,4,4,-;testmod: version magic 'a' should be 'REQUIRED-VALUE'\n"
		"6,5,5,-;random: crng init done\n";
	const char *log_unterminated =
		"6,1,1,-;testmod: version magic 'a' should be 'NO-END-QUOTE\n";
	const char *log_empty_required =
		"6,1,1,-;testmod: version magic 'a' should be ''\n";
	const char *log_no_newline =
		"6,1,1,-;testmod: version magic 'a' should be 'END-WITHOUT-NL'";

	CHECK(lkm_extract_required_vermagic(log_header, strlen(log_header), out,
					    sizeof(out)) == 0 &&
		      !strcmp(out, k_required),
	      "kmsg record not extracted: %s", out);
	CHECK(lkm_extract_required_vermagic(log_plain, strlen(log_plain), out,
					    sizeof(out)) == 0 &&
		      !strcmp(out, k_required),
	      "plain line not extracted: %s", out);
	CHECK(lkm_extract_required_vermagic(log_two, strlen(log_two), out,
					    sizeof(out)) == 0 &&
		      !strcmp(out, "NEW-REQUIRED"),
	      "last record did not win: %s", out);
	CHECK(lkm_extract_required_vermagic(log_decoy, strlen(log_decoy), out,
					    sizeof(out)) == 0 &&
		      !strcmp(out, "REQUIRED-VALUE"),
	      "decoy log not handled: %s", out);
	CHECK(lkm_extract_required_vermagic(log_unterminated,
					    strlen(log_unterminated), out,
					    sizeof(out)) == ENOENT,
	      "unterminated record was accepted");
	CHECK(lkm_extract_required_vermagic(log_empty_required,
					    strlen(log_empty_required), out,
					    sizeof(out)) == ENOENT,
	      "empty required vermagic was accepted");
	CHECK(lkm_extract_required_vermagic(log_no_newline,
					    strlen(log_no_newline), out,
					    sizeof(out)) == 0 &&
		      !strcmp(out, "END-WITHOUT-NL"),
	      "final line without newline not extracted: %s", out);
	CHECK(lkm_extract_required_vermagic("", 0, out, sizeof(out)) == ENOENT,
	      "empty log did not return ENOENT");
	CHECK(lkm_extract_required_vermagic(log_header, strlen(log_header),
					    tiny, sizeof(tiny)) ==
		      ENAMETOOLONG,
	      "small output buffer did not return ENAMETOOLONG");
	CHECK(lkm_extract_required_vermagic(NULL, 0, out, sizeof(out)) ==
		      EINVAL,
	      "NULL log did not return EINVAL");
}

/* ---- 3. .modinfo rewrite ----------------------------------------------- */

static void test_rewrite(void)
{
	unsigned char raw[4096];
	unsigned char snapshot[4096];
	struct lkm_buffer b;
	char detail[LKM_INSMOD_DETAIL_MAX];
	char value[LKM_INSMOD_VERMAGIC_MAX];
	size_t total;

	/* Longer required value: the image must grow and the section header
	 * must be repointed, while the other entries survive in order. */
	total = build_test_module(raw, sizeof(raw), 1, 1, 1);
	CHECK(total > 0, "module fixture build failed");
	snapshot[0] = 0;
	if (total > 0) {
		memcpy(snapshot, raw, total);
		own_image(&b, raw, total);
		CHECK(lkm_modinfo_get(b.data, b.len, "vermagic", value,
				      sizeof(value)) == 0 &&
			      !strcmp(value, k_foreign),
		      "precondition: fixture vermagic is %s", value);

		detail[0] = '\0';
		CHECK(lkm_rewrite_vermagic(&b, k_required, detail,
					   sizeof(detail)) == 0,
		      "rewrite failed: %s", detail);
		CHECK(b.len > total, "rewritten image did not grow");
		CHECK(b.cap >= b.len, "buffer capacity below length");
		CHECK(lkm_modinfo_get(b.data, b.len, "vermagic", value,
				      sizeof(value)) == 0 &&
			      !strcmp(value, k_required),
		      "vermagic after rewrite: %s", value);
		CHECK(lkm_modinfo_get(b.data, b.len, "name", value,
				      sizeof(value)) == 0 &&
			      !strcmp(value, "testmod"),
		      "name entry lost: %s", value);
		CHECK(lkm_modinfo_get(b.data, b.len, "license", value,
				      sizeof(value)) == 0 &&
			      !strcmp(value, "GPL"),
		      "license entry lost: %s", value);
		CHECK(modinfo_count(b.data, b.len, "vermagic") == 1,
		      "vermagic entries after rewrite: %d",
		      modinfo_count(b.data, b.len, "vermagic"));
		CHECK(modinfo_size(b.data) ==
			      strlen("name=testmod") + 1 +
				      strlen("license=GPL") + 1 +
				      strlen("vermagic=") + strlen(k_required) + 1,
		      "section size after rewrite: %llu",
		      (unsigned long long)modinfo_size(b.data));
		CHECK(modinfo_offset(b.data) == b.len - modinfo_size(b.data),
		      "new section not at the end: off=%llu size=%llu len=%zu",
		      (unsigned long long)modinfo_offset(b.data),
		      (unsigned long long)modinfo_size(b.data), b.len);
		CHECK(t64(b.data + 40) == t64(snapshot + 40),
		      "section header table moved");
		CHECK(!memcmp(b.data, snapshot, 4), "ELF magic damaged");

		/* Optional independent check: export the rewritten image so a
		 * real ELF reader (readelf) can confirm it, e.g.
		 *   LKM_INSMOD_TEST_DUMP=/tmp/r.ko ./build/lkm_insmod_test
		 *   readelf -h -S -p .modinfo /tmp/r.ko */
		{
			const char *dump = getenv("LKM_INSMOD_TEST_DUMP");

			if (dump && *dump) {
				FILE *f = fopen(dump, "wb");

				if (f) {
					fwrite(b.data, 1, b.len, f);
					fclose(f);
				}
			}
		}

		/* A second, shorter rewrite must replace, not duplicate. */
		detail[0] = '\0';
		CHECK(lkm_rewrite_vermagic(&b, "SHORT", detail,
					   sizeof(detail)) == 0,
		      "second rewrite failed: %s", detail);
		CHECK(lkm_modinfo_get(b.data, b.len, "vermagic", value,
				      sizeof(value)) == 0 &&
			      !strcmp(value, "SHORT"),
		      "second rewrite value: %s", value);
		CHECK(modinfo_count(b.data, b.len, "vermagic") == 1,
		      "vermagic duplicated after second rewrite: %d",
		      modinfo_count(b.data, b.len, "vermagic"));
		lkm_buffer_free(&b);
	}

	/* Alignment: a .modinfo that requires 8 bytes must land aligned. */
	total = build_test_module(raw, sizeof(raw), 1, 1, 8);
	if (total > 0) {
		own_image(&b, raw, total);
		detail[0] = '\0';
		CHECK(lkm_rewrite_vermagic(&b, k_required, detail,
					   sizeof(detail)) == 0,
		      "aligned rewrite failed: %s", detail);
		CHECK(modinfo_offset(b.data) % 8 == 0,
		      "new section offset %llu is not 8-byte aligned",
		      (unsigned long long)modinfo_offset(b.data));
		lkm_buffer_free(&b);
	}

	/* No vermagic entry: the rewrite appends one. */
	{
		unsigned char mi[256];
		size_t mlen = 0;

		mlen = put_entry(mi, sizeof(mi), mlen, "name=testmod");
		mlen = put_entry(mi, sizeof(mi), mlen, "license=GPL");
		total = build_module(raw, sizeof(raw), mi, mlen, 1, 1);
		CHECK(total > 0, "module fixture (no vermagic) failed");
		if (total > 0) {
			own_image(&b, raw, total);
			detail[0] = '\0';
			CHECK(lkm_rewrite_vermagic(&b, k_required, detail,
						   sizeof(detail)) == 0,
			      "append rewrite failed: %s", detail);
			CHECK(lkm_modinfo_get(b.data, b.len, "vermagic", value,
					      sizeof(value)) == 0 &&
				      !strcmp(value, k_required),
			      "appended vermagic: %s", value);
			CHECK(modinfo_count(b.data, b.len, "vermagic") == 1,
			      "appended vermagic count: %d",
			      modinfo_count(b.data, b.len, "vermagic"));
			lkm_buffer_free(&b);
		}
	}

	/* No .modinfo at all: explicit error, image untouched. */
	total = build_test_module(raw, sizeof(raw), 1, 0, 1);
	CHECK(total > 0, "module fixture (no modinfo) failed");
	if (total > 0) {
		own_image(&b, raw, total);
		memcpy(snapshot, raw, total);
		detail[0] = '\0';
		CHECK(lkm_rewrite_vermagic(&b, k_required, detail,
					   sizeof(detail)) == ENOENT,
		      "missing .modinfo did not return ENOENT");
		CHECK(detail[0] != '\0', "missing .modinfo produced no detail");
		CHECK(b.len == total && !memcmp(b.data, snapshot, total),
		      "failed rewrite modified the image");
		lkm_buffer_free(&b);
	}

	/* Truncated ELF: explicit ENOEXEC, image untouched. */
	total = build_test_module(raw, sizeof(raw), 1, 1, 1);
	if (total > 0) {
		own_image(&b, raw, 32);
		memcpy(snapshot, b.data, 32);
		detail[0] = '\0';
		CHECK(lkm_rewrite_vermagic(&b, k_required, detail,
					   sizeof(detail)) == ENOEXEC,
		      "truncated ELF did not return ENOEXEC");
		CHECK(b.len == 32 && !memcmp(b.data, snapshot, 32),
		      "failed truncated rewrite modified the image");
		lkm_buffer_free(&b);
	}

	/* Bad required strings. */
	{
		char too_long[LKM_INSMOD_VERMAGIC_MAX + 8];

		total = build_test_module(raw, sizeof(raw), 1, 1, 1);
		own_image(&b, raw, total);
		CHECK(lkm_rewrite_vermagic(&b, "", detail, sizeof(detail)) ==
			      EINVAL,
		      "empty required vermagic was accepted");
		memset(too_long, 'x', sizeof(too_long) - 1);
		too_long[sizeof(too_long) - 1] = '\0';
		CHECK(lkm_rewrite_vermagic(&b, too_long, detail,
					   sizeof(detail)) == EINVAL,
		      "over-long required vermagic was accepted");
		CHECK(b.len == total, "failed validation grew the image");
		lkm_buffer_free(&b);
	}
}

/* ---- 4. exactly one retry ---------------------------------------------- */

struct fake_load {
	int calls;
	int rc[4];
	int log_reads;
	const char *log;
	char seen[4][LKM_INSMOD_VERMAGIC_MAX];
};

static int fake_load_fn(void *ctx, const void *data, size_t len,
			const char *params)
{
	struct fake_load *f = ctx;
	int i = f->calls++;

	(void)params;
	if (i < 4)
		(void)lkm_modinfo_get(data, len, "vermagic", f->seen[i],
				      sizeof(f->seen[i]));
	if (i >= 4)
		return EINVAL;
	return f->rc[i];
}

static int fake_log_fn(void *ctx, char *out, size_t out_len)
{
	struct fake_load *f = ctx;
	size_t n;

	f->log_reads++;
	if (!f->log)
		return -EIO;
	n = strlen(f->log);
	if (n + 1 > out_len)
		n = out_len - 1;
	memcpy(out, f->log, n);
	out[n] = '\0';
	return (int)n;
}

static void run_case(const char *name, unsigned char *raw, size_t total,
		     int rc0, int rc1, const char *log, int want_rc,
		     int want_attempts, int want_rewritten, int want_calls,
		     int want_log_reads, const char *detail_match)
{
	struct lkm_buffer b;
	struct fake_load f;
	struct lkm_insmod_ops ops;
	struct lkm_insmod_result r;
	int rc;

	memset(&f, 0, sizeof(f));
	f.rc[0] = rc0;
	f.rc[1] = rc1;
	f.log = log;
	ops.ctx = &f;
	ops.load = fake_load_fn;
	ops.read_log = fake_log_fn;
	own_image(&b, raw, total);
	memset(&r, 0, sizeof(r));

	rc = lkm_insmod_exec(&b, "a=1", &ops, &r);
	CHECK(rc == want_rc, "%s: rc=%d want %d", name, rc, want_rc);
	CHECK(r.err == want_rc, "%s: result.err=%d want %d", name, r.err,
	      want_rc);
	CHECK(r.attempts == want_attempts, "%s: attempts=%d want %d", name,
	      r.attempts, want_attempts);
	CHECK(r.rewritten == want_rewritten, "%s: rewritten=%d want %d", name,
	      r.rewritten, want_rewritten);
	CHECK(f.calls == want_calls, "%s: load calls=%d want %d", name,
	      f.calls, want_calls);
	CHECK(f.log_reads == want_log_reads, "%s: log reads=%d want %d", name,
	      f.log_reads, want_log_reads);
	if (detail_match)
		CHECK(strstr(r.detail, detail_match) != NULL,
		      "%s: detail %s does not contain \"%s\"", name,
		      r.detail, detail_match);
	if (want_rewritten) {
		CHECK(!strcmp(r.required, k_required),
		      "%s: captured required vermagic %s", name, r.required);
		CHECK(!strcmp(f.seen[1], k_required),
		      "%s: second load saw %s, not the rewritten vermagic",
		      name, f.seen[1]);
	}
	lkm_buffer_free(&b);
}

static void test_retry(void)
{
	unsigned char raw[4096];
	unsigned char raw_no_modinfo[4096];
	unsigned char raw_no_vermagic[4096];
	char log[1024];
	size_t total;
	const char *no_vermagic_log =
		"6,1,1,-;testmod: unknown symbol in module\n";

	snprintf(log, sizeof(log),
		 "6,1,1,-;testmod: version magic '%s' should be '%s'\n",
		 k_foreign, k_required);

	total = build_test_module(raw, sizeof(raw), 1, 1, 1);
	CHECK(total > 0, "retry fixture failed");
	if (!total)
		return;

	/* First attempt works: one call, no log read. */
	run_case("first-success", raw, total, 0, 0, NULL, 0, 1, 0, 1, 0,
		 NULL);
	fprintf(stderr, "ok: first attempt success does not touch the log\n");

	/* ENOEXEC with a matching record: rewrite, retry once, succeed. */
	run_case("retry-success", raw, total, ENOEXEC, 0, log, 0, 2, 1, 2, 1,
		 NULL);
	fprintf(stderr, "ok: ENOEXEC is retried exactly once and succeeds\n");

	/* Both attempts fail: two calls and an explicit error, never a third. */
	run_case("retry-fails", raw, total, ENOEXEC, ENOEXEC, log, ENOEXEC, 2,
		 1, 2, 1, "retried exactly once");
	fprintf(stderr, "ok: a failed retry reports the second failure\n");

	/* ENOEXEC but the log has no vermagic record: no blind retry. */
	run_case("no-record", raw, total, ENOEXEC, 0, no_vermagic_log,
		 ENOEXEC, 1, 0, 1, 1, "no complete");
	fprintf(stderr, "ok: ENOEXEC without a vermagic record is not retried\n");

	/* The kernel log cannot be read: no blind retry. */
	run_case("log-unreadable", raw, total, ENOEXEC, 0, NULL, ENOEXEC, 1, 0,
		 1, 1, "could not be read");
	fprintf(stderr, "ok: unreadable kernel log is reported\n");

	/* A non-ENOEXEC failure is not a vermagic problem. */
	run_case("perm", raw, total, EPERM, 0, log, EPERM, 1, 0, 1, 0,
		 "no vermagic retry");
	fprintf(stderr, "ok: EPERM is not treated as a vermagic mismatch\n");

	/* ENOEXEC, record present, but the image has no .modinfo to rewrite. */
	total = build_test_module(raw_no_modinfo, sizeof(raw_no_modinfo), 1, 0,
				  1);
	CHECK(total > 0, "no-modinfo fixture failed");
	if (total)
		run_case("rewrite-impossible", raw_no_modinfo, total, ENOEXEC, 0,
			 log, ENOEXEC, 1, 0, 1, 1, ".modinfo");
	fprintf(stderr, "ok: an image with no .modinfo is not retried\n");

	/* ENOEXEC with an empty required value: not a usable record. */
	{
		char empty_log[512];

		snprintf(empty_log, sizeof(empty_log),
			 "6,1,1,-;testmod: version magic '%s' should be ''\n",
			 k_foreign);
		total = build_test_module(raw_no_vermagic, sizeof(raw_no_vermagic),
					  1, 1, 1);
		CHECK(total > 0, "empty-required fixture failed");
		if (total)
			run_case("empty-required", raw_no_vermagic, total, ENOEXEC,
				 0, empty_log, ENOEXEC, 1, 0, 1, 1,
				 "no complete");
		fprintf(stderr, "ok: an empty required vermagic is not retried\n");
	}
}

/* ---- 5. file loading --------------------------------------------------- */

static void test_buffer_read(void)
{
	char path[] = "/tmp/lkm-ins-buf-XXXXXX";
	struct lkm_buffer b;
	char detail[LKM_INSMOD_DETAIL_MAX];
	int fd;
	int rc;

	/* mkstemp needs the template but creates the file. */
	fd = mkstemp(path);
	CHECK(fd >= 0, "mkstemp: %s", strerror(errno));
	if (fd < 0)
		return;
	CHECK(write(fd, "hello", 5) == 5, "write fixture: %s", strerror(errno));
	close(fd);

	lkm_buffer_init(&b);
	detail[0] = '\0';
	rc = lkm_buffer_read_file(&b, path, detail, sizeof(detail));
	CHECK(rc == 0, "read file failed: %s", detail);
	CHECK(b.len == 5 && !memcmp(b.data, "hello", 5),
	      "read file contents wrong (len=%zu)", b.len);
	lkm_buffer_free(&b);

	/* Re-reading replaces, and a missing file is an explicit ENOENT. */
	rc = lkm_buffer_read_file(&b, "/tmp/definitely-not-there-lkmins", detail,
				  sizeof(detail));
	CHECK(rc == ENOENT, "missing file returned %d", rc);
	CHECK(detail[0] != '\0', "missing file produced no detail");

	/* Empty file is refused rather than treated as a module. */
	{
		char empty[] = "/tmp/lkm-ins-empty-XXXXXX";
		int efd = mkstemp(empty);

		CHECK(efd >= 0, "mkstemp empty: %s", strerror(errno));
		if (efd >= 0) {
			close(efd);
			rc = lkm_buffer_read_file(&b, empty, detail,
						  sizeof(detail));
			CHECK(rc == ENOEXEC, "empty file returned %d", rc);
			unlink(empty);
		}
	}

	CHECK(lkm_buffer_read_file(&b, NULL, detail, sizeof(detail)) == EINVAL,
	      "NULL path did not return EINVAL");
	lkm_buffer_free(&b);
	unlink(path);
}

int main(void)
{
	printf("lkm_insmod host tests\n\n");

	test_paths();
	test_extract();
	test_confirm();
	test_rewrite();
	test_abi_layout();
	test_abi_nobits();
	test_retry();
	test_buffer_read();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
