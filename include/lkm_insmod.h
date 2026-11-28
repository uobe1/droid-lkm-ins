/* SPDX-License-Identifier: GPL-2.0-only
 *
 * lkm_insmod.h - the testable core of the insmod front end.
 *
 * This is the part of `lkmctl insmod` that does not talk to the kernel
 * directly, so it can be exercised on the host:
 *
 *   - canonicalize a module path (the same thing ksud and apd do before they
 *     read a module, and what the success line reports);
 *   - read the module's declared vermagic from its .modinfo section without
 *     scanning unrelated bytes;
 *   - pull the vermagic the kernel demands out of the kernel log record
 *     `... version magic 'X' should be 'Y' ...`;
 *   - rewrite .modinfo to carry Y, growing the section if it must - the same
 *     shape as KernelSU's ksuinit;
 *   - load once, and on ENOEXEC rewrite and retry exactly once.
 *
 * Error convention: every function returns 0 on success and a positive
 * errno value on failure.  That is the user-space convention (the kernel
 * returns negative errno from syscalls, which the caller converts); it keeps
 * this layer independent from lkm_loader.h's LKM_* codes.
 *
 * No function fabricates success.  A load that did not happen returns an
 * errno; a rewrite that could not be done leaves the image untouched and says
 * why.
 */
#ifndef LKM_INSMOD_H
#define LKM_INSMOD_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* The exact sentence a user must type twice to force an unadaptable module. */
#define LKM_UNSAFE_CONFIRM_SENTENCE "YES I AGREE LOAD THIS UNSAFE MODULE"

/* The kernel's vermagic is short; anything longer is not a vermagic and is
 * rejected rather than allowed to grow a module unboundedly. */
#define LKM_INSMOD_VERMAGIC_MAX 256

/* Human-readable reason; sized for one wrapped sentence. */
#define LKM_INSMOD_DETAIL_MAX 256

/* Cap for the kernel-log records collected between the two load attempts. */
#define LKM_INSMOD_LOG_MAX 32768

/*
 * An owned module image.  `len` is the file length, `cap` the allocated size.
 * A vermagic rewrite can append a new .modinfo section at the end, so the
 * buffer may be reallocated by lkm_rewrite_vermagic().
 */
struct lkm_buffer {
	unsigned char *data;
	size_t len;
	size_t cap;
};

void lkm_buffer_init(struct lkm_buffer *buf);
void lkm_buffer_free(struct lkm_buffer *buf);

/* Grow the allocation to hold at least `need` bytes.  Existing contents are
 * preserved.  Returns 0 or ENOMEM. */
int lkm_buffer_reserve(struct lkm_buffer *buf, size_t need);

/* Read a whole file into the buffer, replacing its contents.  Returns 0 or a
 * positive errno; an empty file is refused with ENOEXEC and a reason. */
int lkm_buffer_read_file(struct lkm_buffer *buf, const char *path, char *detail, size_t detail_len);

/*
 * Resolve `path` to a canonical absolute path (symlinks, "..", "." and a
 * relative prefix all resolved).  Returns 0 or a positive errno; EINVAL for an
 * empty path, ENAMETOOLONG when the result does not fit, and the realpath(3)
 * errno when the file cannot be resolved.
 */
int lkm_canonicalize_path(const char *path, char *out, size_t out_len);

/*
 * Read one key from the module's .modinfo section.  `key` is the bare name
 * ("vermagic", not "vermagic=").  The result is NUL-terminated; the section is
 * located through the ELF section table, so strings elsewhere in the file are
 * never mistaken for modinfo.
 *
 * Returns 0, ENOENT when the key is absent, ENOEXEC when the image is not a
 * usable ELF64 relocatable object, ENAMETOOLONG when `out` is too small, or
 * EINVAL on a bad argument.
 */
int lkm_modinfo_get(const unsigned char *data, size_t len, const char *key, char *out,
		    size_t out_len);

/*
 * Extract the second string of the kernel's
 *     version magic 'X' should be 'Y'
 * record from `log_text`.
 *
 * `log_text` is whole records separated by newlines; a leading kmsg record
 * header ("6,123,456,-;") is stripped at the first ';'.  When several records
 * match, the last one wins: it is the most recent, and therefore the one the
 * failed load just produced.  Returns 0, ENOENT when no complete record is
 * present, ENAMETOOLONG when `out` is too small, or EINVAL on a bad argument.
 */
int lkm_extract_required_vermagic(const char *log_text, size_t log_len, char *out, size_t out_len);

/*
 * Rewrite the image's vermagic entry to `required`.
 *
 * The .modinfo section is rebuilt (other entries preserved and in order), a
 * fresh copy is appended at the end of the image aligned to the section's
 * sh_addralign, and the section header's sh_offset/sh_size are updated.  The
 * original bytes are left in place, exactly like ksuinit's rewrite.
 *
 * The image is left untouched on every failure.  Returns 0 or a positive
 * errno with a reason in `detail`: ENOENT when there is no .modinfo section,
 * ENOEXEC when the image is malformed, EINVAL for an unusable required string,
 * or ENOMEM.
 */
int lkm_rewrite_vermagic(struct lkm_buffer *buf, const char *required, char *detail,
			 size_t detail_len);

/*
 * The kernel's `struct module` layout, read from /sys/kernel/btf/vmlinux.
 *
 * A module's `.gnu.linkonce.this_module` section is generated by the module
 * build from the headers of whatever kernel it was built against.  When those
 * headers do not match the running kernel, the section size and the
 * init/exit/name field offsets are wrong, and the kernel may load the module
 * but then treat it as unloadable (exit read as NULL) or corrupt state.
 *
 * The loader therefore reads the real layout from the running kernel's BTF and
 * adapts the module's section before init_module(2), instead of requiring a
 * per-kernel module build.
 */
struct lkm_module_layout {
	size_t size;	 /* sizeof(struct module) */
	size_t name_off; /* byte offset of name[] */
	size_t init_off; /* byte offset of init */
	size_t exit_off; /* byte offset of exit; SIZE_MAX when absent */
	int have_exit;
};

/*
 * Parse `btf_path` (normally /sys/kernel/btf/vmlinux) and return the layout of
 * `struct module`.  Returns 0, ENOENT when there is no such struct, ENOEXEC
 * for a malformed BTF, or a positive errno.
 */
int lkm_btf_module_layout(const char *btf_path, struct lkm_module_layout *layout, char *detail,
			  size_t detail_len);

/*
 * Rewrite `buf`'s `.gnu.linkonce.this_module` section and its relocation
 * entries to match `layout`, so the kernel reads name/init/exit where it
 * expects them.
 *
 * The section is rebuilt at the aligned end of the image with exactly
 * `layout->size` bytes, the module name is placed at `layout->name_off`, and
 * the existing init_module/cleanup_module relocations are moved to
 * `layout->init_off` / `layout->exit_off`.  Other fields are zero: the kernel
 * initializes them.
 *
 * Returns 0 (also when the image already matches), ENOENT when the section or
 * a required relocation is missing, EINVAL for an unusable layout/name, or
 * ENOMEM.  The image is untouched on failure.
 */
int lkm_adapt_module_layout(struct lkm_buffer *buf, const struct lkm_module_layout *layout,
			    const char *module_name, char *detail, size_t detail_len);

/*
 * Interactive confirmation for forcing a module whose struct module layout
 * cannot be adapted (it may load but never be unloadable).
 *
 * Prompts on `out` and reads two lines from `in`.  Each line, with the trailing
 * newline removed, must be exactly LKM_UNSAFE_CONFIRM_SENTENCE.  Returns 0 only
 * when both lines match; ECANCELED otherwise (including EOF), with a reason
 * printed on `out`.  The caller is responsible for the TTY check: this helper
 * never pretends a non-interactive stream is a user.
 */
int lkm_confirm_unsafe_load(FILE *in, FILE *out);

/*
 * The two operations the retry driver needs from its caller.  Both return 0 on
 * success and a positive errno on failure.  `read_log` returns the number of
 * bytes written into `out` (NUL-terminated), or a negative errno when the
 * kernel log cannot be read.  `load` is init_module(2) in production and a
 * counting fake in tests.
 */
struct lkm_insmod_ops {
	void *ctx;
	int (*load)(void *ctx, const void *data, size_t len, const char *params);
	int (*read_log)(void *ctx, char *out, size_t out_len);
};

struct lkm_insmod_result {
	int attempts;  /* 1 or 2; never more */
	int rewritten; /* .modinfo was rewritten before the second attempt */
	int first_errno;
	int err; /* errno to report to the user; 0 on success */
	char required[LKM_INSMOD_VERMAGIC_MAX];
	char detail[LKM_INSMOD_DETAIL_MAX];
};

/*
 * Load an image, retrying once and only once when the kernel answers ENOEXEC
 * and its log names a required vermagic.
 *
 * Cases:
 *   - first load succeeds            -> attempts=1, no log read
 *   - first error is not ENOEXEC     -> attempts=1, no log read
 *   - ENOEXEC, log unreadable        -> attempts=1, explicit detail
 *   - ENOEXEC, no vermagic record    -> attempts=1, explicit detail
 *   - ENOEXEC, rewrite impossible    -> attempts=1, explicit detail
 *   - ENOEXEC, rewritten, retry ok   -> attempts=2, rewritten=1
 *   - ENOEXEC, rewritten, retry fails-> attempts=2, explicit detail
 *
 * Returns 0 or the errno to report.  `result->err` carries the same value.
 */
int lkm_insmod_exec(struct lkm_buffer *buf, const char *params, const struct lkm_insmod_ops *ops,
		    struct lkm_insmod_result *result);

#endif /* LKM_INSMOD_H */
