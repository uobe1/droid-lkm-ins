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
static int report_vermagic(const char *modinfo, size_t len)
{
	static const char key[] = "vermagic=";
	const char *p = modinfo;
	size_t keylen = sizeof(key) - 1;

	while ((size_t)(p - modinfo) < len) {
		size_t left = len - (size_t)(p - modinfo);
		size_t n = strnlen(p, left);

		if (n >= keylen && !strncmp(p, key, keylen)) {
			char want[256];
			int f;
			size_t got = 0;

			printf("vermagic: %.*s\n", (int)(n - keylen), p + keylen);
			f = open("/proc/version", O_RDONLY);
			if (f >= 0) {
				got = (size_t)read(f, want, sizeof(want) - 1);
				close(f);
				if (got) {
					want[got] = '\0';
					printf("kernel:   %s", want);
				}
			}
			return 0;
		}
		p += n + 1;
	}
	printf("vermagic: (not present in .modinfo)\n");
	return 0;
}

/*
 * Read one NUL-separated key from a module's .modinfo blob.  Returns a pointer
 * into `data` (not a copy), or NULL when the key is absent.
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

/* The kernel release, without the trailing newline. */
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

	/*
	 * Refuse a vermagic that cannot match, before loading.
	 *
	 * The kernel would reject it too, but only with ENOEXEC: the useful fact
	 * -- which part of the string differs -- is lost.  Checking here turns
	 * "the kernel said no" into "this module was built for X, you are running
	 * Y".  The check is not a substitute for the kernel's own validation, and
	 * it does not patch anything; it only reports earlier and more precisely.
	 */
	{
		char detail[192] = "";
		const char *mv = find_modinfo_value(data, len, "vermagic");

		if (mv) {
			if (lkm_check_vermagic(mv, uname_release(), detail,
					       sizeof(detail)) != LKM_OK) {
				fprintf(stderr,
					"lkmctl: vermagic mismatch: %s\n  refusing to load %s\n",
					detail, opt.module);
				/* The symbol table has not been loaded yet, so only the
				 * module buffer exists to release here. */
				free(data);
				return 1;
			}
		} else {
			fprintf(stderr,
				"lkmctl: %s has no vermagic; refusing (the kernel would "
				"reject it, and a module without one cannot be validated)\n",
				opt.module);
			free(data);
			lkm_kallsyms_free(&ks);
			return 1;
		}
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
	 * init_module(2) parses the image again, relocates it and runs init.  The
	 * kernel does the work; we only handed it a module whose non-exported
	 * references already point at real addresses.
	 */
	errno = 0;
	ret = (int)syscall(__NR_init_module, data, len, opt.params);
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
				"  the kernel rejected the image; check vermagic and "
				"that every required symbol resolved\n");
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
