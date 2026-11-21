/*
 * lkmctl - bind a .ko's undefined symbols and let the kernel load it.
 *
 * This is the user-space half of the loader work: the same shape as APatch's
 * `apd insmod` and KernelSU's `ksud insmod`/ksuinit.  It reads the module,
 * binds undefined symbols against /proc/kallsyms at their real addresses, then
 * calls init_module(2) so the kernel does the allocation, relocation and
 * lifecycle itself.
 *
 * When the kernel rejects the image with ENOEXEC because of a vermagic
 * mismatch, the required vermagic is read back from the kernel log, the
 * module's .modinfo section is rewritten, and the load is retried exactly
 * once - the same shape as ksuinit.  The rewrite is announced loudly; a
 * module built for another kernel can load and then misbehave in ways that are
 * harder to diagnose than a refusal.  If the log does not name a required
 * vermagic, the failure is reported as-is and no blind retry happens.
 *
 * Symbol resolution is deliberately only /proc/kallsyms: this loader works
 * without the KernelSU driver.  Symbols that kptr_restrict hides are reported
 * as failures, never papered over.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -Werror -std=c11 -Iinclude \
 *      -DLKM_BIND_IMPLEMENTATION -DLKM_KALLSYMS_IMPLEMENTATION \
 *      -DLKM_LOADER_IMPLEMENTATION \
 *      src/lkmctl.c src/lkm_insmod.c -o lkmctl
 *
 * Usage:
 *   lkmctl insmod <module.ko> [param=value ...]
 *   lkmctl rmmod  <name> [--force]
 *   lkmctl bind   <module.ko>
 *   lkmctl check  <module.ko>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lkm_bind.h"
#include "lkm_insmod.h"
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
		"usage: lkmctl insmod [--force] <module.ko> [param=value ...]\n"
		"       lkmctl rmmod  <name> [--force]\n"
		"       lkmctl bind   <module.ko>\n"
		"       lkmctl check  <module.ko>\n"
		"\n"
		"insmod  bind undefined symbols, then call init_module(2)\n"
		"rmmod   call delete_module(2); --force passes O_TRUNC to the kernel\n"
		"bind    rewrite a copy in memory and report (no load)\n"
		"check   only report which symbols resolve\n"
		"\n"
		"--force  insmod only: allow a module whose struct module layout cannot\n"
		"         be adapted to this kernel.  Requires a TTY and typing the\n"
		"         confirmation sentence twice; the module may be unloadable.\n");
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

/*
 * Report the image's declared vermagic against the running kernel.  Used only
 * on the failure path, to make an ENOEXEC actionable instead of a bare errno.
 */
static void report_vermagic(const struct lkm_buffer *img)
{
	char mv[LKM_INSMOD_VERMAGIC_MAX];
	char detail[192] = "";
	int rc = lkm_modinfo_get(img->data, img->len, "vermagic", mv, sizeof(mv));

	if (rc != 0) {
		printf("vermagic: (not present in .modinfo)\n");
		return;
	}
	printf("vermagic: %s\n", mv);
	printf("kernel:   %s\n", uname_release());
	if (lkm_check_vermagic(mv, uname_release(), detail, sizeof(detail)) !=
	    LKM_OK)
		printf("mismatch: %s\n", detail);
}

/* ---- kernel log access -------------------------------------------------- */

/*
 * The kernel log is opened before the first load attempt and drained to the
 * current end.  Reads afterwards therefore return only the records the failed
 * load produced, never an older mismatch from some other module.
 *
 * ksuinit opens the same devices with O_NONBLOCK and seeks to the end; the
 * drain gives the same guarantee without depending on lseek() on /dev/kmsg.
 */
struct kmsg_ctx {
	int fd;
	int open_errno;
};

static int kmsg_open(struct kmsg_ctx *kmsg)
{
	static const char *paths[] = { "/dev/kmsg", "/kmsg" };
	char record[16384];
	size_t i;

	kmsg->fd = -1;
	kmsg->open_errno = 0;

	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		int fd = open(paths[i], O_RDONLY | O_NONBLOCK | O_CLOEXEC);

		if (fd < 0) {
			kmsg->open_errno = errno;
			continue;
		}
		kmsg->fd = fd;
		break;
	}
	if (kmsg->fd < 0)
		return kmsg->open_errno;

	/* Discard everything that is already in the ring buffer. */
	for (;;) {
		ssize_t n = read(kmsg->fd, record, sizeof(record));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			kmsg->open_errno = errno;
			close(kmsg->fd);
			kmsg->fd = -1;
			return kmsg->open_errno;
		}
		if (n == 0)
			break;
	}
	return 0;
}

static void kmsg_close(struct kmsg_ctx *kmsg)
{
	if (kmsg->fd >= 0)
		close(kmsg->fd);
	kmsg->fd = -1;
}

static int kmsg_read_new(void *ctx, char *out, size_t out_len)
{
	struct kmsg_ctx *kmsg = ctx;
	size_t used = 0;

	if (kmsg->fd < 0)
		return -kmsg->open_errno;

	for (;;) {
		ssize_t n;

		if (out_len - used < 2)
			break;
		n = read(kmsg->fd, out + used, out_len - used - 2);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return -errno;
		}
		if (n == 0)
			break;
		/* One record per read; separate records the way ksuinit does. */
		out[used + (size_t)n] = '\n';
		used += (size_t)n + 1;
	}
	if (used < out_len)
		out[used] = '\0';
	return (int)used;
}

/* ---- load callback: the kernel syscall ---------------------------------- */

static int cli_load(void *ctx, const void *data, size_t len, const char *params)
{
	(void)ctx;
	errno = 0;
	if (syscall(__NR_init_module, data, len, params) == 0)
		return 0;
	return errno ? errno : EIO;
}

int main(int argc, char **argv)
{
	struct opts opt = { 0 };
	struct lkm_kallsyms ks;
	struct lkm_kallsyms_lookup_ctx lc;
	struct lkm_symtab st;
	struct lkm_bind_stats stats;
	struct lkm_fs fs = { NULL, lkm_fs_read_file, lkm_fs_write_file };
	struct lkm_buffer img;
	struct lkm_insmod_ops ops = { NULL, cli_load, kmsg_read_new };
	struct lkm_insmod_result result;
	struct kmsg_ctx kmsg;
	char diag[256] = "";
	char *joined = NULL; /* owned; opt.params points at it when present */
	char *fargs[256];
	char **args = argv;
	int nargs = argc;
	int force = 0;
	int i, ret;

	if (argc < 3) {
		usage();
		return 2;
	}

	/* rmmod takes a module NAME, not a path, and does not read the image.
	 * It is handled before any path canonicalization for exactly that
	 * reason: "kernelsu" is a name, not a file. */
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

	/* --force is an insmod-only safety override; module parameters are
	 * key=value, so it can be filtered anywhere without ambiguity. */
	if (opt.do_load) {
		int w = 0;

		if (argc > (int)(sizeof(fargs) / sizeof(fargs[0]))) {
			fprintf(stderr, "lkmctl: too many arguments\n");
			return 2;
		}
		fargs[w++] = argv[0];
		fargs[w++] = argv[1];
		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--force")) {
				force = 1;
				continue;
			}
			fargs[w++] = argv[i];
		}
		args = fargs;
		nargs = w;
	} else {
		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--force")) {
				fprintf(stderr,
					"lkmctl: --force is only valid for insmod\n");
				return 2;
			}
		}
	}
	if (nargs < 3) {
		usage();
		return 2;
	}

	/*
	 * Resolve the path first, as ksud and apd both do: a relative path that
	 * is valid from the caller's cwd can stop being valid once the module's
	 * init runs, and the path is also what gets reported on success.  A path
	 * that cannot be resolved is an error, not something to guess around.
	 */
	{
		/* Static storage: opt.module outlives this block and is printed on
		 * success, so a block-local buffer would leave it dangling. */
		static char resolved[PATH_MAX];
		int r = lkm_canonicalize_path(args[2], resolved, sizeof(resolved));

		if (r != 0) {
			fprintf(stderr, "lkmctl: cannot resolve module path %s: %s\n",
				args[2], strerror(r));
			return 1;
		}
		opt.module = resolved;
	}

	/* Remaining arguments are module parameters, joined with spaces the way
	 * init_module expects them. */
	if (opt.do_load && nargs > 3) {
		size_t total = 1;
		char *w;

		for (i = 3; i < nargs; i++)
			total += strlen(args[i]) + 1;
		joined = malloc(total);
		if (!joined) {
			perror("malloc");
			return 1;
		}
		w = joined;
		for (i = 3; i < nargs; i++) {
			size_t n = strlen(args[i]);

			if (i > 3)
				*w++ = ' ';
			memcpy(w, args[i], n);
			w += n;
		}
		*w = '\0';
		opt.params = joined;
	} else {
		opt.params = "";
	}

	lkm_buffer_init(&img);
	ret = lkm_buffer_read_file(&img, opt.module, diag, sizeof(diag));
	if (ret != 0) {
		fprintf(stderr, "lkmctl: %s\n", diag);
		lkm_buffer_free(&img);
		free(joined);
		return 1;
	}

	memset(&ks, 0, sizeof(ks));
	ret = lkm_kallsyms_load(&fs, &ks);
	if (ret < 0) {
		fprintf(stderr,
			"lkmctl: cannot read usable symbols from /proc/kallsyms (%d).\n"
			"  kptr_restrict may be hiding addresses; run as root.\n", ret);
		lkm_buffer_free(&img);
		free(joined);
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
	ret = lkm_bind_symbols(img.data, img.len, &st, &stats, diag, sizeof(diag));
	printf("bind: undefined=%u bound=%u unresolved=%u%s%s\n",
	       stats.undefined, stats.bound, stats.unresolved,
	       diag[0] ? " -- " : "", diag);
	if (ret != LKM_BIND_OK) {
		fprintf(stderr, "lkmctl: binding failed: %s\n", diag);
		lkm_buffer_free(&img);
		lkm_kallsyms_free(&ks);
		free(joined);
		return 1;
	}
	if (opt.verbose && stats.unresolved)
		printf("note: %u symbol(s) left for the kernel to resolve\n",
		       stats.unresolved);

	if (!opt.do_load) {
		printf("not loaded (bind/check only)\n");
		lkm_buffer_free(&img);
		lkm_kallsyms_free(&ks);
		free(joined);
		return 0;
	}

	/*
	 * A module's .gnu.linkonce.this_module carries the kernel's struct
	 * module layout from the headers it was built against.  When that build
	 * is not the running kernel, the event that matters is not "vermagic
	 * mismatch" but "the kernel reads init/exit from the wrong offsets":
	 * observed as a module that loads and can never be unloaded because exit
	 * is read as NULL.  Read the real layout from the running kernel's BTF
	 * and adapt the section before init_module(2).
	 */
	{
		struct lkm_module_layout layout;
		char layout_detail[LKM_INSMOD_DETAIL_MAX];
		char namebuf[64];
		const char *module_name = NULL;
		size_t before = img.len;

		if (lkm_modinfo_get(img.data, img.len, "name", namebuf,
				    sizeof(namebuf)) == 0)
			module_name = namebuf;

		if (!module_name) {
			fprintf(stderr,
				"lkmctl: refusing to load a module with no name= in "
				".modinfo: its struct module layout cannot be "
				"adapted\n");
			lkm_buffer_free(&img);
			lkm_kallsyms_free(&ks);
			free(joined);
			return 1;
		}

		{
			int layout_ok = 0;
			char layout_reason[LKM_INSMOD_DETAIL_MAX] = "";

			if (lkm_btf_module_layout("/sys/kernel/btf/vmlinux", &layout,
						  layout_detail,
						  sizeof(layout_detail)) != 0) {
				snprintf(layout_reason, sizeof(layout_reason),
					 "no usable kernel BTF: %.180s", layout_detail);
			} else if (lkm_adapt_module_layout(&img, &layout, module_name,
							   layout_detail,
							   sizeof(layout_detail)) != 0) {
				snprintf(layout_reason, sizeof(layout_reason),
					 "module ABI layout cannot be adapted: %.160s",
					 layout_detail);
			} else {
				layout_ok = 1;
				if (img.len != before)
					fprintf(stderr,
						"[WARN] module .this_module layout differed "
						"from this kernel; adapted to the kernel BTF "
						"layout (struct module %zu bytes)\n",
						layout.size);
			}

			if (!layout_ok) {
				if (!force) {
					fprintf(stderr,
						"lkmctl: refusing to load: %s\n"
						"  the module's struct module layout is not "
						"safe for this kernel; it may load but never "
						"be unloadable.  Re-run with `--force` to "
						"attempt it with an interactive confirmation.\n",
						layout_reason);
					lkm_buffer_free(&img);
					lkm_kallsyms_free(&ks);
					free(joined);
					return 1;
				}
				if (!isatty(STDIN_FILENO) ||
				    !isatty(STDERR_FILENO)) {
					fprintf(stderr,
						"lkmctl: refusing --force load without a TTY: "
						"cannot obtain the interactive confirmation\n");
					lkm_buffer_free(&img);
					lkm_kallsyms_free(&ks);
					free(joined);
					return 1;
				}
				fprintf(stderr,
					"[DANGER] forcing a module whose layout cannot be "
					"adapted to this kernel: %s\n"
					"[DANGER] the kernel may load it and never be able "
					"to unload it.\n", layout_reason);
				if (lkm_confirm_unsafe_load(stdin, stderr) != 0) {
					fprintf(stderr,
						"lkmctl: load aborted; module not loaded\n");
					lkm_buffer_free(&img);
					lkm_kallsyms_free(&ks);
					free(joined);
					return 1;
				}
			}
		}
	}

	/* Open and drain the kernel log before the first attempt, so the retry
	 * path can only see records this load produced. */
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.fd = -1;
	ops.ctx = &kmsg;
	if (kmsg_open(&kmsg) != 0)
		fprintf(stderr,
			"[WARN] cannot read the kernel log (%s); a vermagic retry "
			"will be impossible\n", strerror(kmsg.open_errno));

	memset(&result, 0, sizeof(result));
	ret = lkm_insmod_exec(&img, opt.params, &ops, &result);
	kmsg_close(&kmsg);

	if (ret != 0) {
		fprintf(stderr, "lkmctl: init_module failed: %s (%d)\n",
			strerror(ret), ret);
		if (result.detail[0])
			fprintf(stderr, "  %s\n", result.detail);
		if (result.attempts == 2)
			fprintf(stderr,
				"  vermagic was rewritten to '%s' and the load was "
				"retried once\n", result.required);
		switch (ret) {
		case EPERM:
			fprintf(stderr, "  not permitted: run as root in a domain "
					"allowed to load modules\n");
			break;
		case ENOEXEC:
			if (result.attempts == 1)
				fprintf(stderr,
					"  the image was rejected; no vermagic "
					"rewrite/retry was attempted\n");
			report_vermagic(&img);
			break;
		case EEXIST:
			fprintf(stderr, "  a module with this name is already loaded\n");
			break;
		}
		lkm_buffer_free(&img);
		lkm_kallsyms_free(&ks);
		free(joined);
		return 1;
	}

	if (result.rewritten) {
		/*
		 * A bypass must be loud.  This is the only place a rewrite is
		 * reported as something that happened; nothing warns about a
		 * bypass that was not performed.
		 */
		fprintf(stderr,
			"[WARN] vermagic mismatch was bypassed: the module declared "
			"a different vermagic than this kernel requires; .modinfo was "
			"rewritten to '%s' and the load retried once\n",
			result.required);
		fprintf(stderr,
			"[WARN] the module is now loaded against a mismatch the kernel "
			"would normally refuse; verify its behaviour\n");
	}

	printf("Loaded kernel module: %s\n", opt.module);
	lkm_buffer_free(&img);
	lkm_kallsyms_free(&ks);
	free(joined);
	return 0;
}
