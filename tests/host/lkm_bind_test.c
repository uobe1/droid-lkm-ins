/*
 * Host tests for lkm_bind.h + lkm_kallsyms.h.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -Werror -std=c11 -I tools/lkml \
 *      -DLKM_BIND_IMPLEMENTATION -DLKM_KALLSYMS_IMPLEMENTATION \
 *      tests/host/lkm_bind_test.c -o /tmp/lkm_bind_test && /tmp/lkm_bind_test
 *
 * The point of these tests is the behaviour both references depend on:
 * symbol entries are rewritten to SHN_ABS with the kernel address, unresolved
 * symbols are reported but do not abort, and /proc/kallsyms parsing stops at
 * the first module symbol so it cannot shadow a kernel one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lkm_bind.h"
#include "lkm_kallsyms.h"

static int checks;
static int failures;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		failures++; \
		printf("FAIL %s\n", msg); \
	} \
} while (0)

/* ---------------- a minimal ELF64 builder ---------------- */

#define SEC_NULL 0
#define SEC_SYMTAB 1
#define SEC_STRTAB 2
#define SEC_COUNT 3

struct builder {
	unsigned char buf[4096];
	size_t len;
};

static void put16(unsigned char *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(unsigned char *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(unsigned char *p, uint64_t v) { memcpy(p, &v, 8); }

/* One symbol to place in the table. */
struct symspec {
	const char *name;
	uint16_t shndx;
	uint64_t value;
};

static void build_module(struct builder *b, const struct symspec *syms, int nsyms)
{
	const size_t ehsize = 64;
	const size_t shentsize = 64;
	size_t symtab_off = ehsize;
	size_t symtab_size = (size_t)(nsyms + 1) * 24;
	size_t strtab_off = symtab_off + symtab_size;
	size_t strtab_size = 0;
	size_t shoff;
	unsigned char *eh = b->buf;
	unsigned char *symtab;
	unsigned char *strtab;
	unsigned char *shdrs;
	int i;

	memset(b, 0, sizeof(*b));

	/* string table: "" then each name */
	strtab_size = 1;
	for (i = 0; i < nsyms; i++)
		strtab_size += strlen(syms[i].name) + 1;

	shoff = strtab_off + strtab_size;
	if (shoff % 8)
		shoff += 8 - (shoff % 8);

	/* ELF header */
	memcpy(eh, "\177ELF", 4);
	eh[4] = 2;   /* ELFCLASS64 */
	eh[5] = 1;   /* little endian */
	eh[6] = 1;   /* version */
	put16(eh + 16, 1);   /* ET_REL */
	put16(eh + 18, 183); /* EM_AARCH64 */
	put32(eh + 20, 1);
	put64(eh + 40, shoff);
	put16(eh + 52, (uint16_t)ehsize);
	put16(eh + 58, (uint16_t)shentsize);
	put16(eh + 60, SEC_COUNT);
	put16(eh + 62, 0);

	/* symtab: entry 0 null, then the specs */
	symtab = b->buf + symtab_off;
	strtab = b->buf + strtab_off;
	{
		size_t off = 1;
		for (i = 0; i < nsyms; i++) {
			unsigned char *s = symtab + (size_t)(i + 1) * 24;
			put32(s, (uint32_t)off);
			s[4] = 0x10; /* STB_GLOBAL / STT_NOTYPE */
			s[5] = 0;
			put16(s + 6, syms[i].shndx);
			put64(s + 8, syms[i].value);
			put64(s + 16, 0);
			strcpy((char *)strtab + off, syms[i].name);
			off += strlen(syms[i].name) + 1;
		}
		strtab[0] = '\0';
	}

	/* section headers */
	shdrs = b->buf + shoff;
	/* [0] null section stays zeroed */
	/* [1] .symtab */
	put32(shdrs + shentsize + 0, 0);
	put32(shdrs + shentsize + 4, 2); /* SHT_SYMTAB */
	put64(shdrs + shentsize + 24, symtab_off);
	put64(shdrs + shentsize + 32, symtab_size);
	put32(shdrs + shentsize + 40, SEC_STRTAB); /* sh_link */
	put32(shdrs + shentsize + 44, 1);
	put64(shdrs + shentsize + 56, 24);         /* sh_entsize */
	/* [2] .strtab */
	put32(shdrs + 2 * shentsize + 4, 3); /* SHT_STRTAB */
	put64(shdrs + 2 * shentsize + 24, strtab_off);
	put64(shdrs + 2 * shentsize + 32, strtab_size);

	b->len = shoff + SEC_COUNT * shentsize;
}

/* Read back the symbol entry the binder should have rewritten. */
static void read_symbol(const struct builder *b, int index, uint16_t *shndx,
			uint64_t *value)
{
	const unsigned char *p = b->buf + 64 + (size_t)index * 24;

	memcpy(shndx, p + 6, 2);
	memcpy(value, p + 8, 8);
}

/* ---------------- fake kallsyms ---------------- */

static uint64_t fake_lookup(void *ctx, const char *name)
{
	const struct {
		const char *name;
		uint64_t addr;
	} *table = ctx;
	int i;

	for (i = 0; table[i].name; i++) {
		if (!strcmp(table[i].name, name))
			return table[i].addr;
	}
	return 0;
}

static const struct {
	const char *name;
	uint64_t addr;
} kern_syms[] = {
	{ "printk", 0xffff800010000000ULL },
	{ "kallsyms_lookup_name", 0xffff800010010000ULL },
	{ NULL, 0 },
};

/* ---------------- tests ---------------- */

static void test_binds_undefined_symbols(void)
{
	struct symspec syms[] = {
		{ "printk", LKM_SHN_UNDEF, 0 },
		{ "kallsyms_lookup_name", LKM_SHN_UNDEF, 0 },
		{ "module_local", 3, 0x10 },   /* already defined: must not change */
	};
	struct builder b;
	struct lkm_symtab st = { (void *)kern_syms, fake_lookup, NULL };
	struct lkm_bind_stats stats;
	char diag[256] = "";
	uint16_t shndx;
	uint64_t value;
	int ret;

	build_module(&b, syms, 3);
	ret = lkm_bind_symbols(b.buf, b.len, &st, &stats, diag, sizeof(diag));
	CHECK(ret == LKM_BIND_OK, "binding a well-formed module must succeed");
	CHECK(stats.undefined == 2, "two undefined symbols expected");
	CHECK(stats.bound == 2, "both must be bound");
	CHECK(stats.unresolved == 0, "nothing should remain unresolved");

	read_symbol(&b, 1, &shndx, &value);
	CHECK(shndx == LKM_SHN_ABS, "bound symbol must become SHN_ABS");
	CHECK(value == 0xffff800010000000ULL, "bound symbol must carry the address");

	read_symbol(&b, 3, &shndx, &value);
	CHECK(shndx == 3, "an already-defined symbol must keep its section");
	CHECK(value == 0x10, "an already-defined symbol must keep its value");
}

static void test_unresolved_is_reported_not_fatal(void)
{
	struct symspec syms[] = {
		{ "printk", LKM_SHN_UNDEF, 0 },
		{ "does_not_exist", LKM_SHN_UNDEF, 0 },
	};
	struct builder b;
	struct lkm_symtab st = { (void *)kern_syms, fake_lookup, NULL };
	struct lkm_bind_stats stats;
	char diag[256] = "";
	uint16_t shndx;
	uint64_t value;
	int ret;

	build_module(&b, syms, 2);
	ret = lkm_bind_symbols(b.buf, b.len, &st, &stats, diag, sizeof(diag));
	/*
	 * Both references leave unknown symbols for init_module instead of failing,
	 * so a bind that aborts here would reject images the kernel accepts.
	 */
	CHECK(ret == LKM_BIND_OK, "an unknown symbol must not abort the bind");
	CHECK(stats.bound == 1, "the known symbol is still bound");
	CHECK(stats.unresolved == 1, "the unknown symbol is counted");

	read_symbol(&b, 2, &shndx, &value);
	CHECK(shndx == LKM_SHN_UNDEF, "the unknown symbol stays undefined");
	CHECK(value == 0, "the unknown symbol keeps a zero value");
}

static void test_rejects_non_relocatable(void)
{
	struct builder b;
	struct lkm_symtab st = { (void *)kern_syms, fake_lookup, NULL };
	char diag[256] = "";

	build_module(&b, NULL, 0);
	b.buf[16] = 2; /* ET_EXEC */
	CHECK(lkm_bind_symbols(b.buf, b.len, &st, NULL, diag, sizeof(diag)) != LKM_BIND_OK,
	      "a non-relocatable object must be refused");

	build_module(&b, NULL, 0);
	b.buf[4] = 1; /* ELFCLASS32 */
	CHECK(lkm_bind_symbols(b.buf, b.len, &st, NULL, diag, sizeof(diag)) != LKM_BIND_OK,
	      "a 32-bit object must be refused");

	build_module(&b, NULL, 0);
	b.buf[18] = 62; /* x86-64 */
	CHECK(lkm_bind_symbols(b.buf, b.len, &st, NULL, diag, sizeof(diag)) != LKM_BIND_OK,
	      "a foreign architecture must be refused");
}

static void test_rejects_truncated(void)
{
	struct builder b;
	struct lkm_symtab st = { (void *)kern_syms, fake_lookup, NULL };
	char diag[256] = "";
	struct symspec syms[] = { { "printk", LKM_SHN_UNDEF, 0 } };

	build_module(&b, syms, 1);
	/* Point the section table past the end of the buffer. */
	put64(b.buf + 40, b.len + 512);
	CHECK(lkm_bind_symbols(b.buf, b.len, &st, NULL, diag, sizeof(diag)) != LKM_BIND_OK,
	      "an out-of-range section table must be refused");

	build_module(&b, syms, 1);
	CHECK(lkm_bind_symbols(b.buf, 32, &st, NULL, diag, sizeof(diag)) != LKM_BIND_OK,
	      "a truncated header must be refused");
}

static void test_suffix_stripping(void)
{
	char buf[128];

	CHECK(!strcmp(lkm_strip_symbol_suffix("printk", buf, sizeof(buf)), "printk"),
	      "a plain name is returned as-is");
	CHECK(!strcmp(lkm_strip_symbol_suffix("printk.cfi_jt", buf, sizeof(buf)), "printk"),
	      ".cfi_jt must be stripped");
	CHECK(!strcmp(lkm_strip_symbol_suffix("foo$abc", buf, sizeof(buf)), "foo"),
	      "$ variants must be folded to the plain name");
	CHECK(!strcmp(lkm_strip_symbol_suffix("bar.llvm.1234", buf, sizeof(buf)), "bar"),
	      ".llvm.NNN clones must be folded");
}

static void test_kallsyms_parse_stops_at_modules(void)
{
	const char *text =
		"ffff800010000000 T printk\n"
		"ffff800010010000 T kallsyms_lookup_name\n"
		"ffffffffc0001000 t module_symbol\tmymod\t[mymod]\n";
	struct lkm_kallsyms ks;

	memset(&ks, 0, sizeof(ks));
	CHECK(lkm_kallsyms_parse(text, strlen(text), &ks) == 2,
	      "module symbols must end the kernel list");
	CHECK(ks.count == 2, "only kernel symbols are stored");
	CHECK(!strcmp(ks.syms[0].name, "printk"), "first symbol parsed");
	CHECK(ks.syms[0].addr == 0xffff800010000000ULL, "address parsed as hex");
	lkm_kallsyms_free(&ks);
}

static void test_kallsyms_parse_skips_zero_addresses(void)
{
	/* kptr_restrict defeated the read: every address is zero. */
	const char *text =
		"0000000000000000 T printk\n"
		"0000000000000000 T kallsyms_lookup_name\n";
	struct lkm_kallsyms ks;

	memset(&ks, 0, sizeof(ks));
	CHECK(lkm_kallsyms_parse(text, strlen(text), &ks) < 0,
	      "an all-zero table must fail instead of binding address 0");
	lkm_kallsyms_free(&ks);
}

static void test_searched_symbols_do_not_hit_module_entries(void)
{
	/*
	 * A kernel symbol and a module symbol with the same name: the kernel one
	 * must win, which is exactly why parsing stops at the first module line.
	 */
	const char *text =
		"ffff800010000000 T printk\n"
		"ffffffffc0002000 T printk\totherm\t[otherm]\n";
	struct lkm_kallsyms ks;
	struct lkm_kallsyms_lookup_ctx lc;

	memset(&ks, 0, sizeof(ks));
	lkm_kallsyms_parse(text, strlen(text), &ks);
	lc.ks = &ks;
	lc.misses = 0;
	CHECK(lkm_kallsyms_lookup(&lc, "printk") == 0xffff800010000000ULL,
	      "the kernel symbol must win over the module symbol");
	lkm_kallsyms_free(&ks);
}

static void test_abi_version(void)
{
	CHECK(lkm_bind_abi_version() == LKM_BIND_ABI_VERSION,
	      "reported ABI version must equal the macro");
}

int main(void)
{
	printf("lkm_bind host tests\n");
	test_binds_undefined_symbols();
	test_unresolved_is_reported_not_fatal();
	test_rejects_non_relocatable();
	test_rejects_truncated();
	test_suffix_stripping();
	test_kallsyms_parse_stops_at_modules();
	test_kallsyms_parse_skips_zero_addresses();
	test_searched_symbols_do_not_hit_module_entries();
	test_abi_version();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	printf(failures == 0 ? "LKM_BIND_OK\n" : "LKM_BIND_FAIL\n");
	return failures == 0 ? 0 : 1;
}
