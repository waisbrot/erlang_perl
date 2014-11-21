# This Makefile builds the dependencies (libjs and libnspr) needed by
# spidermonkey_drv.so

UNAME	:= $(shell uname -s)
TAR		?= tar
GUNZIP		?= gunzip
SMONKEY_VER	:= 1.8.0-rc1
NSPR_VER	:= 4.8

ifeq ($(UNAME),SunOS)
	PATCH	?= gpatch
else
	PATCH	?= patch
endif

SYSTEM_DIR := $(CURDIR)/system
LIB_DIR    := $(SYSTEM_DIR)/lib
INC_DIR    := $(SYSTEM_DIR)/include

JS_DIR     := $(CURDIR)/js
NSPR_DIR   := $(CURDIR)/nsprpub

# NSPR_SIXTYFOUR is defined in erlang_js/rebar.config

js:


clean:
	@rm -rf $(SYSTEM_DIR) $(NSPR_DIR) $(JS_DIR)
	@rm -rf *flymake*

nspryoink: deps
	@cd deps ; \
	@cvs -q -d :pserver:anonymous@cvs-mirror.mozilla.org:/cvsroot \
		co -r NSPR_4_8_RTM -d nsprpub mozilla/nsprpub

.EXPORT_ALL_VARIABLES:
