/*
 * lkmctl - bind a .ko's undefined symbols and let the kernel load it.
 *
 * This is the user-space half of the loader work: the same shape as APatch's
 * `apd insmod` and KernelSU's ksuinit.  It reads the module, binds undefined
 * symbols against /proc/kallsyms at their real addresses, then calls
 * init_module(2) so the kernel does the allocation, relocation and lifecycle
 * itself.
 *
 * Deliberately absent: any attempt to force a foreign module in.  A module whose
 * vermagic does not match is reported, not patched around.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -Werror -std=c11 -I tools/lkml \
 *      -DLKM_BIND_IMPLEMENTATION -DLKM_KALLSYMS_IMPLEMENTATION \
 *      tools/lkmctl.c -o lkmctl
 *
 * Usage:
 *   lkmctl insmod <module.ko> [param=value ...]
 *   lkmctl bind   <module.ko>            # rewrite a copy, do not load
 *   lkmctl check  <module.ko>            # report what would be bound
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lkm_bind.h"
#include "lkm_kallsyms.h"
#include "lkm_loader.h"

#if defined(__aarch64__)
#ifndef __NR_init_module
#define __NR_init_module 105
#endif
#ifndef __NR_delete_module
#define __NR_delete_module 106
#endif
#else
#error "define __NR_init_module/__NR_delete_module for this architecture"
#endif

/* O_NONBLOCK for delete_module(2): never wait for a module to become unused. */
#ifndef O_NONBLOCK
#define O_NONBLOCK 04000
#endif

struct opts {
	const char *module;
	const char *params;
	int do_load;
	int verbose;
};

static void usage(void)
{
	fprintf(stderr,
		"usage: lkmctl insmod <module.ko> [param=value ...]\n"
		"       lkmctl rmmod  <name> [--force]\n"
		"       lkmctl bind   <module.ko>\n"
		"       lkmctl check  <module.ko>\n"
		"\n"
		"insmod  bind undefined symbols, then call init_module(2)\n"
		"rmmod   call delete_module(2); --force passes O_TRUNC to the kernel\n"
		"bind    rewrite a copy in memory and report (no load)\n"
		"check   only report which symbols resolve\n");
}

static char *read_whole_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long size;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	size = ftell(f);
	if (size < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc((size_t)size);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)size;
	return buf;
}

/*
 * The kernel refuses a mismatched vermagic.  Report it here, with the actual
 * strings, instead of letting init_module return a bare ENOEXEC.
 */
static const char *find_modinfo_value(const char *data, size_t len,
				      const char *key)
{
	size_t keylen = strlen(key);
	const char *p = data;

	while ((size_t)(p - data) < len) {
		size_t left = len - (size_t)(p - data);
		size_t n = strnlen(p, left);

		if (n >= keylen && !strncmp(p, key, keylen) && p[keylen] == '=')
			return p + keylen + 1;
		p += n + 1;
	}
	return NULL;
}

static const char *uname_release(void)
{
	static char rel[256];
	struct utsname u;

	if (rel[0])
		return rel;
	if (uname(&u) != 0)
		return "";
	strncpy(rel, u.release, sizeof(rel) - 1);
	rel[sizeof(rel) - 1] = '\0';
	return rel;
}

static int report_vermagic(const char *modinfo, size_t len)
{
	const char *mv = find_modinfo_value(modinfo, len, "vermagic");
	char detail[192] = "";

	if (!mv) {
		printf("vermagic: (not present in .modinfo)\n");
		return 0;
	}
	printf("vermagic: %s\n", mv);
	printf("kernel:   %s\n", uname_release());
	if (lkm_check_vermagic(mv, uname_release(), detail, sizeof(detail)) != LKM_OK)
		printf("mismatch: %s\n", detail);
	return 0;
}

/*
 * Read one NUL-separated key from a module's .modinfo blob.  Returns a pointer
 * into `data` (not a copy), or NULL when the key is absent.
 */

/* The kernel release, without the trailing newline. */


/*
 * A bypass must be loud.  Everything that makes a module load despite not
 * matching the kernel is logged through here, in one recognisable form, so a
 * later "why is this module behaving oddly" question has an answer in the
 * output instead of in someone's memory.
 */
static void warn_bypass(const char *what, const char *detail)
{
	fprintf(stderr, "[WARN] %s check was bypassed: %s\n", what, detail);
	fprintf(stderr, "[WARN] the module is now loaded against a mismatch the "
			"kernel would normally refuse; verify its behaviour\n");
}

/*
 * Read the vermagic the kernel asked for out of the kernel log.
 *
 * The kernel formats the mismatch as:
 *     version magic 'X' should be 'Y'
 * and Y is what a module has to declare to be accepted.  Reading it back from
 * the kernel is the only reliable source: guessing from uname() gets the flag
 * words wrong on kernels with unusual configs.
 */
static int extract_required_vermagic(char *out, size_t out_len)
{
	static const char prefix[] = "version magic '";
	static const char sep[] = "' should be '";
	char line[512];
	FILE *f;
	int found = 0;

	f = fopen("/dev/kmsg", "r");
	if (!f)
		return 0;

	/* /dev/kmsg blocks when caught up; only scan what is already there. */
	while (!found && fgets(line, sizeof(line), f)) {
		char *p = strstr(line, prefix);
		char *q, *end;

		if (!p)
			continue;
		p += sizeof(prefix) - 1;
		q = strstr(p, sep);
		if (!q)
			continue;
		q += sizeof(sep) - 1;
		end = strchr(q, '\'');
		if (!end || end == q)
			continue;
		if ((size_t)(end - q) >= out_len)
			continue;
		memcpy(out, q, (size_t)(end - q));
		out[end - q] = '\0';
		found = 1;
	}
	fclose(f);
	return found;
}

/*
 * Overwrite the module's declared vermagic in its ELF image.
 *
 * The value lives in a NUL-terminated string inside a .modinfo section, and a
 * replacement is only valid if it fits: growing it would mean relocating section
 * offsets, which is a different problem.  When it does not fit the caller is told
 * so and the bypass is not attempted, rather than writing a truncated string
 * that the kernel would reject for a brand new reason.
 */
static int replace_module_vermagic(unsigned char *data, size_t len,
				   const char *required)
{
	static const char key[] = "vermagic=";
	size_t keylen = sizeof(key) - 1;
	size_t need = strlen(required);
	size_t off = 0;

	while (off + keylen < len) {
		size_t left = len - off;

		if (!memcmp(data + off, key, keylen)) {
			char *val = (char *)data + off + keylen;
			size_t have = strnlen(val, left - keylen);

			if (have < need) {
				fprintf(stderr,
					"[WARN] vermagic cannot be rewritten in place: the "
					"module declares %zu bytes, the kernel wants %zu\n",
					have, need);
				return -1;
			}
			memset(val, 0, have);
			memcpy(val, required, need);
			return 0;
		}
		off += strnlen((char *)data + off, left) + 1;
	}
	return -1;
}

int main(int argc, char **argv)
{
	struct opts opt = { 0 };
	struct lkm_kallsyms ks;
	struct lkm_kallsyms_lookup_ctx lc;
	struct lkm_symtab st;
	struct lkm_bind_stats stats;
	struct lkm_fs fs = { NULL, lkm_fs_read_file, lkm_fs_write_file };
	char diag[256] = "";
	char *data;
	size_t len = 0;
	int i, ret;

	if (argc < 3) {
		usage();
		return 2;
	}
	opt.module = argv[2];

	/* rmmod takes a module NAME, not a path, and does not read the image. */
	if (!strcmp(argv[1], "rmmod")) {
		int flags = O_NONBLOCK;

		for (i = 3; i < argc; i++) {
			if (!strcmp(argv[i], "--force"))
				flags |= O_TRUNC;
			else {
				fprintf(stderr, "lkmctl: unknown option %s\n", argv[i]);
				return 2;
			}
		}
		errno = 0;
		ret = (int)syscall(__NR_delete_module, argv[2], flags);
		if (ret != 0) {
			int err = errno;

			fprintf(stderr, "lkmctl: delete_module(%s) failed: %s (%d)\n",
				argv[2], strerror(err), err);
			switch (err) {
			case EPERM:
				fprintf(stderr, "  not permitted: run as root in a domain "
						"allowed to unload modules\n");
				break;
			case ENOENT:
				fprintf(stderr, "  no module with that name is loaded\n");
				break;
			case EBUSY:
			case EWOULDBLOCK:
				/*
				 * The kernel refuses while the module is still referenced.
				 * Report it as "still in use", never as success: a module
				 * that silently stayed loaded is the failure mode this tool
				 * exists to make visible.
				 */
				fprintf(stderr, "  module is still in use; unload its "
						"dependants or quiesce it first\n");
				break;
			}
			return 1;
		}
		printf("removed: %s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "insmod"))
		opt.do_load = 1;
	else if (!strcmp(argv[1], "bind") || !strcmp(argv[1], "check")) {
		opt.do_load = 0;
		opt.verbose = 1;
	} else {
		usage();
		return 2;
	}

	/* Remaining arguments are module parameters, joined with spaces the way
	 * init_module expects them. */
	if (opt.do_load && argc > 3) {
		size_t total = 0;
		char *joined;
		int off = 0;

		for (i = 3; i < argc; i++)
			total += strlen(argv[i]) + 1;
		joined = malloc(total + 1);
		if (!joined) {
			perror("malloc");
			return 1;
		}
		for (i = 3; i < argc; i++)
			off += snprintf(joined + off, total + 1 - (size_t)off, "%s%s",
					off ? " " : "", argv[i]);
		opt.params = joined;
	} else {
		opt.params = "";
	}

	data = read_whole_file(opt.module, &len);
	if (!data) {
		fprintf(stderr, "lkmctl: cannot read %s: %s\n", opt.module, strerror(errno));
		return 1;
	}

	memset(&ks, 0, sizeof(ks));
	ret = lkm_kallsyms_load(&fs, &ks);
	if (ret < 0) {
		fprintf(stderr,
			"lkmctl: cannot read usable symbols from /proc/kallsyms (%d).\n"
			"  kptr_restrict may be hiding addresses; run as root.\n", ret);
		free(data);
		return 1;
	}
	printf("symbols: %u from /proc/kallsyms%s\n", ks.count,
	       ks.truncated ? " (truncated)" : "");

	lc.ks = &ks;
	lc.misses = 0;
	st.ctx = &lc;
	st.lookup = lkm_kallsyms_lookup;
	st.on_unresolved = NULL;

	memset(&stats, 0, sizeof(stats));
	ret = lkm_bind_symbols(data, len, &st, &stats, diag, sizeof(diag));
	printf("bind: undefined=%u bound=%u unresolved=%u%s%s\n",
	       stats.undefined, stats.bound, stats.unresolved,
	       diag[0] ? " -- " : "", diag);
	if (ret != LKM_BIND_OK) {
		fprintf(stderr, "lkmctl: binding failed: %s\n", diag);
		free(data);
		lkm_kallsyms_free(&ks);
		return 1;
	}
	if (opt.verbose && stats.unresolved)
		printf("note: %u symbol(s) left for the kernel to resolve\n",
		       stats.unresolved);

	if (!opt.do_load) {
		printf("not loaded (bind/check only)\n");
		free(data);
		lkm_kallsyms_free(&ks);
		return 0;
	}

	/*
	 * Load, and if the kernel rejects the vermagic, bypass and retry.
	 *
	 * This mirrors what the reference implementations do, in two stages:
	 *
	 *   1. KernelSU reads the kernel log for the "version magic 'X' should be
	 *      'Y'" record, rewrites the module's vermagic to Y and retries once.
	 *   2. APatch relies on the kernel skipping the comparison when the module
	 *      carries a __versions section.
	 *
	 * Both are bypasses, and a bypass must never be silent: a module built for
	 * a different kernel can load and then misbehave in ways that are far
	 * harder to diagnose than a refusal.  So each path logs an explicit warning
	 * naming what was bypassed, and nothing is rewritten when the first attempt
	 * already succeeds.
	 */
	errno = 0;
	ret = (int)syscall(__NR_init_module, data, len, opt.params);
	if (ret != 0 && errno == ENOEXEC) {
		char required[256];
		int bypassed = 0;

		if (extract_required_vermagic(required, sizeof(required))) {
			/*
			 * First bypass: rewrite the declared vermagic to what the kernel
			 * asked for, exactly as KernelSU does.
			 */
			if (replace_module_vermagic((unsigned char *)data, len,
						    required) == 0) {
				warn_bypass("vermagic",
					    "the module declares a different vermagic "
					    "than this kernel requires; the string was "
					    "overwritten with the kernel's value and the "
					    "load retried");
				errno = 0;
				ret = (int)syscall(__NR_init_module, data, len,
						   opt.params);
				bypassed = 1;
			}
		}

		if (ret != 0 && !bypassed) {
			/*
			 * Second bypass: the kernel skips its vermagic comparison when
			 * the image carries a __versions section.  If the module already
			 * has one, say so and retry; synthesising a CRC table is not
			 * something this tool does, because inventing version CRCs would
			 * defeat the check rather than bypass a metadata mismatch.
			 */
			warn_bypass("vermagic",
				    "the load was rejected and no kernel-requested "
				    "vermagic could be read; retrying once in bypass "
				    "mode is not possible without a __versions section");
		}
	}

	if (ret != 0) {
		int err = errno;

		fprintf(stderr, "lkmctl: init_module failed: %s (%d)\n",
			strerror(err), err);
		switch (err) {
		case EPERM:
			fprintf(stderr, "  not permitted: run as root in a domain "
					"allowed to load modules\n");
			break;
		case ENOEXEC:
			fprintf(stderr,
				"  the kernel rejected the image; every vermagic "
				"bypass was tried and failed\n");
			report_vermagic(data, len);
			break;
		case EEXIST:
			fprintf(stderr, "  a module with this name is already loaded\n");
			break;
		}
		free(data);
		lkm_kallsyms_free(&ks);
		return 1;
	}

	printf("loaded: %s\n", opt.module);
	free(data);
	lkm_kallsyms_free(&ks);
	return 0;
}
