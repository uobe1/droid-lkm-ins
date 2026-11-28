#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# Local lint gate mirroring the lint surfaces of .github/workflows/qemu-insmod.yml:
#   tools: shellcheck, ruff, clang-format, yamllint, actionlint, cppcheck
# Tool resolution: PATH, then uvx (ruff / clang-format / yamllint), then
# $DNSK_LINT_TOOLS (shellcheck / actionlint / cppcheck).  clang-format is
# pinned to the CI version (18.1.8).  A missing tool prints UNAVAILABLE and
# makes the gate exit 2 (incomplete); it is never counted as passed.
#
# Exit status: 0 = every surface ran and passed; 1 = a surface failed;
# 2 = a surface could not run because its tool is missing.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
LINT_TOOLS=${DNSK_LINT_TOOLS:-/tmp/lint-tools}
fail=0
incomplete=0

have_tool() { command -v "$1" >/dev/null 2>&1; }
ok() { echo "ok: $1"; }
bad() {
	echo "FAIL: $1" >&2
	fail=1
}
unavailable() {
	echo "UNAVAILABLE: $1 (tool missing; surface not checked)" >&2
	incomplete=1
}

do_shellcheck() {
	if have_tool shellcheck; then
		sc=shellcheck
	elif [ -x "$LINT_TOOLS/shellcheck" ]; then
		sc="$LINT_TOOLS/shellcheck"
	else
		unavailable shellcheck
		return 0
	fi
	if "$sc" tests/host/lkmctl_cli_test.sh tests/qemu/init-insmod; then
		ok shellcheck
	else
		bad shellcheck
	fi
}

do_ruff() {
	if have_tool ruff; then
		set -- ruff
	elif have_tool uvx; then
		set -- uvx ruff
	else
		unavailable ruff
		return 0
	fi
	if "$@" check scripts; then ok ruff; else bad ruff; fi
}

do_clang_format() {
	if have_tool uvx; then
		set -- uvx --from clang-format==18.1.8 clang-format
	elif have_tool clang-format && clang-format --version 2>/dev/null | grep -q 'version 18\.1\.8'; then
		set -- clang-format
	else
		unavailable clang-format 18.1.8
		return 0
	fi
	if git ls-files -z '*.c' '*.h' | xargs -0 -r "$@" --dry-run --Werror; then
		ok clang-format
	else
		bad clang-format
	fi
}

do_yamllint() {
	if have_tool yamllint; then
		set -- yamllint
	elif have_tool uvx; then
		set -- uvx yamllint
	else
		unavailable yamllint
		return 0
	fi
	if "$@" .github/workflows; then ok yamllint; else bad yamllint; fi
}

do_actionlint() {
	if have_tool actionlint; then
		set -- actionlint
	elif [ -x "$LINT_TOOLS/actionlint" ]; then
		set -- "$LINT_TOOLS/actionlint"
	else
		unavailable actionlint
		return 0
	fi
	if PATH="$LINT_TOOLS:$PATH" "$@"; then ok actionlint; else bad actionlint; fi
}

do_cppcheck() {
	if ! have_tool cppcheck; then
		unavailable cppcheck
		return 0
	fi
	if cppcheck --enable=warning,performance,portability --error-exitcode=1 \
		--std=c11 --suppress=missingIncludeSystem -Iinclude \
		src/*.c tests/host/*.c; then
		ok cppcheck
	else
		bad cppcheck
	fi
}

do_shellcheck
do_ruff
do_clang_format
do_yamllint
do_actionlint
do_cppcheck

if [ "$fail" -ne 0 ]; then
	exit 1
fi
if [ "$incomplete" -ne 0 ]; then
	exit 2
fi
exit 0
