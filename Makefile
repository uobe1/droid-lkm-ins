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
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
INC := -Iinclude
OUT ?= build

IMPL_SRC := $(OUT)/lkm_impl.c
HEADERS := include/lkm_bind.h include/lkm_kallsyms.h

.PHONY: all static shared tools test clean

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

$(OUT)/lkmctl: src/lkmctl.c $(IMPL_SRC) $(HEADERS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -DLKM_BIND_IMPLEMENTATION \
		-DLKM_KALLSYMS_IMPLEMENTATION -o $@ src/lkmctl.c

# ---- tests ---------------------------------------------------------------
test: $(OUT)/lkm_bind_test
	./$(OUT)/lkm_bind_test

$(OUT)/lkm_bind_test: tests/host/lkm_bind_test.c $(HEADERS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -DLKM_BIND_IMPLEMENTATION \
		-DLKM_KALLSYMS_IMPLEMENTATION -o $@ tests/host/lkm_bind_test.c

clean:
	rm -rf $(OUT)
