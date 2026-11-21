# SPDX-License-Identifier: GPL-2.0-only
#
# droid-lkm-ins: bind undefined module symbols, then let the kernel load it.
#
#   make            static library + host tests
#   make shared     prebuilt shared libraries (host + aarch64)
#   make tools      the lkmctl binary for the host
#   make test       run the host test suite
#   make clean
#
# The headers are the deliverable; the library targets exist so a consumer can
# link a prebuilt .so instead of compiling the implementation themselves.

CC ?= cc
AR ?= ar
CROSS_AARCH64 ?= aarch64-linux-gnu-gcc
ANDROID_CC ?= $(CROSS_AARCH64)
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
INC := -Iinclude
OUT ?= build

IMPL_SRC := $(OUT)/lkm_impl.c
INSMOD_SRC := src/lkm_insmod.c
HEADERS := include/lkm_bind.h include/lkm_kallsyms.h include/lkm_loader.h \
	include/lkm_insmod.h

.PHONY: all static shared tools android test clean

all: static tools test

$(OUT):
	mkdir -p $(OUT)

$(IMPL_SRC): $(HEADERS) | $(OUT)
	printf '#define LKM_BIND_IMPLEMENTATION\n#define LKM_KALLSYMS_IMPLEMENTATION\n#include "%s"\n#include "%s"\n' \
		"$(abspath include/lkm_bind.h)" "$(abspath include/lkm_kallsyms.h)" > $@

# ---- static library -------------------------------------------------------
static: $(OUT)/liblkmloader.a

$(OUT)/liblkmloader.a: $(IMPL_SRC) $(HEADERS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -c -o $(OUT)/lkm_impl.o $<
	$(AR) rcs $@ $(OUT)/lkm_impl.o

# ---- shared libraries -----------------------------------------------------
shared: $(OUT)/liblkmloader.so $(OUT)/liblkmloader-aarch64.so

$(OUT)/liblkmloader.so: $(IMPL_SRC) $(HEADERS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -fPIC -shared -DLKM_BIND_SHARED \
		-fvisibility=hidden -o $@ $<

$(OUT)/liblkmloader-aarch64.so: $(IMPL_SRC) $(HEADERS) | $(OUT)
	$(CROSS_AARCH64) $(CFLAGS) $(INC) -fPIC -shared -DLKM_BIND_SHARED \
		-fvisibility=hidden -o $@ $<

# ---- command line front end ----------------------------------------------
tools: $(OUT)/lkmctl

$(OUT)/lkmctl: src/lkmctl.c $(INSMOD_SRC) $(IMPL_SRC) $(HEADERS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -DLKM_BIND_IMPLEMENTATION \
		-DLKM_KALLSYMS_IMPLEMENTATION -DLKM_LOADER_IMPLEMENTATION \
		-o $@ src/lkmctl.c $(INSMOD_SRC)

# ---- Android target -------------------------------------------------------
# There is no bionic sysroot on the development host (only NDK headers), so
# this links statically against the aarch64 glibc cross toolchain.  The result
# has no PT_INTERP: it needs neither /system/bin/linker64 nor
# /lib/ld-linux-aarch64.so.1.  It is a static Linux/Android-kernel executable,
# not a bionic-linked one; running it on a device is the device gate's job.
android: $(OUT)/lkmctl-android

$(OUT)/lkmctl-android: src/lkmctl.c $(INSMOD_SRC) $(IMPL_SRC) $(HEADERS) | $(OUT)
	$(ANDROID_CC) $(CFLAGS) $(INC) -static \
		-DLKM_BIND_IMPLEMENTATION -DLKM_KALLSYMS_IMPLEMENTATION \
		-DLKM_LOADER_IMPLEMENTATION \
		-o $@ src/lkmctl.c $(INSMOD_SRC)

# ---- tests ---------------------------------------------------------------
test: $(OUT)/lkm_bind_test $(OUT)/lkm_insmod_test $(OUT)/lkmctl
	./$(OUT)/lkm_bind_test
	./$(OUT)/lkm_insmod_test
	sh tests/host/lkmctl_cli_test.sh ./$(OUT)/lkmctl

$(OUT)/lkm_bind_test: tests/host/lkm_bind_test.c $(HEADERS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -DLKM_BIND_IMPLEMENTATION \
		-DLKM_KALLSYMS_IMPLEMENTATION -o $@ tests/host/lkm_bind_test.c

$(OUT)/lkm_insmod_test: tests/host/lkm_insmod_test.c $(INSMOD_SRC) \
		include/lkm_insmod.h | $(OUT)
	$(CC) $(CFLAGS) $(INC) -o $@ tests/host/lkm_insmod_test.c $(INSMOD_SRC)

clean:
	rm -rf $(OUT)
