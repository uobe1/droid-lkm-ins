#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# CLI-level negative checks for lkmctl.
#
# These deliberately never reach init_module(2)/delete_module(2): the point is
# that bad invocations fail closed with a non-zero exit and an explicit
# message, instead of printing a success line.  Loading and unloading are
# covered by the host unit tests and, on a device, by the real gate.
set -u

BIN=${1:-./build/lkmctl}
CHECKS=0
FAILS=0

run_expect() {
	desc=$1
	want=$2
	pattern=$3
	shift 3
	CHECKS=$((CHECKS + 1))
	out=$("$@" 2>&1)
	got=$?
	if [ "$got" -ne "$want" ]; then
		echo "FAIL: $desc: exit $got, want $want"
		echo "      output: $out"
		FAILS=$((FAILS + 1))
		return
	fi
	case $out in
	*"$pattern"*) ;;
	*)
		echo "FAIL: $desc: output does not contain '$pattern'"
		echo "      output: $out"
		FAILS=$((FAILS + 1))
		;;
	esac
}

echo "lkmctl CLI tests"

run_expect "no arguments" 2 "usage:" "$BIN"
run_expect "insmod without a path" 2 "usage:" "$BIN" insmod
run_expect "rmmod without a name" 2 "usage:" "$BIN" rmmod
run_expect "unknown subcommand" 2 "usage:" "$BIN" frobnicate /tmp/x.ko

MISSING=/tmp/lkm-ins-definitely-missing.ko
run_expect "insmod missing path" 1 "cannot resolve module path" \
	"$BIN" insmod "$MISSING"
run_expect "insmod --force missing path" 1 "cannot resolve module path" \
	"$BIN" insmod --force "$MISSING"
run_expect "insmod --force without path" 2 "usage:" \
	"$BIN" insmod --force
run_expect "bind rejects --force" 2 "--force is only valid for insmod" \
	"$BIN" bind --force "$MISSING"
run_expect "bind missing path" 1 "cannot resolve module path" \
	"$BIN" bind "$MISSING"
run_expect "check missing path" 1 "cannot resolve module path" \
	"$BIN" check "$MISSING"
run_expect "insmod empty path" 1 "cannot resolve module path" \
	"$BIN" insmod ""

DIR=$(mktemp -d /tmp/lkm-ins-dir-XXXXXX) || {
	echo "FAIL: mktemp -d"
	exit 1
}
run_expect "insmod directory" 1 "cannot read" "$BIN" insmod "$DIR"
rmdir "$DIR"

echo
echo "$CHECKS checks, $FAILS failure(s)"
[ "$FAILS" -eq 0 ]