#
# safe_iop - Makefile
#
# Author:: Will Drewry <redpig@dataspill.org>
# Copyright 2007,2008 redpig@dataspill.org
#
# Unless required by applicable law or agreed to in writing, software
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied.
#

CC = gcc
LN = ln
VERSION = 0.5.0
CPPFLAGS = -Iinclude
CFLAGS   = -Wall -Werror -Wextra -fPIE
SOURCES = src/safe_iop.c
ARCH = $(shell uname -s)
LIB_TARGET = so
# You might want to change this
LIB_INSTALL_PATH = ""

all: lib tests

askme: examples/askme.c include/safe_iop.h
	$(CC) $(CPPFLAGS) $(CFLAGS) examples/askme.c -o $@

manual_tests: lib include/safe_iop.h tests/manual.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNDEBUG=1 tests/manual.c -L$(PWD) -lsafe_iop -o $@

speed_tests: src/safe_iop.c include/safe_iop.h tests/manual.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSAFE_IOP_SPEED_TEST=1 -DNDEBUG=1 tests/manual.c -o $@

autotests: utils/metatests.rb
	ruby -Iutils ./utils/metatests.rb > tests/autotests.c
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/autotests.c -o autotests

tests: autotests manual_tests
	LD_LIBRARY_PATH=$(PWD) ./manual_tests && ./autotests

speed_test: speed_tests
	./speed_tests

clean:
	@rm -f manual_tests autotests tests/autotests.c speed_tests askme libsafe_iop.$(VERSION).dylib libsafe_iop.dylib libsafe_iop.$(VERSION).so libsafe_iop.so 2>/dev/null

# This may be built as a library or directly included in source.
# Unless support for safe_iopf is needed, header inclusion is enough.
lib: src/safe_iop.c include/safe_iop.h
ifeq ($(ARCH),Darwin)
	$(CC) -dynamiclib -Wl,-headerpad_max_install_names,-undefined,dynamic_lookup,-compatibility_version,$(VERSION),-current_version,$(VERSION),-install_name,$(LIB_INSTALL_PATH)libsafe_iop.$(VERSION).dylib $(LDFLAGS) $(SOURCES) -o libsafe_iop.$(VERSION).dylib
	$(LN) -sf libsafe_iop.$(VERSION).dylib libsafe_iop.dylib
else
	$(CC) -shared -Wl,-soname,libsafe_iop.so.$(VERSION) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o libsafe_iop.so.$(VERSION)
	$(LN) -sf libsafe_iop.so.$(VERSION) libsafe_iop.so
endif



