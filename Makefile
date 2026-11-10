NAVISERVER ?= /usr/local/ns
PKG_CONFIG ?= pkg-config
MOD = bcrypt.so
MODOBJS = src/library.o src/crypt/bcrypt.o src/crypt/blowfish.o
BCRYPT_VERSION := $(shell sed -n 's/^project(bcrypt-tcl VERSION \([^ ]*\).*/\1/p' CMakeLists.txt)
CFLAGS += -std=c11 -DUSE_NAVISERVER -DBUILD_bcrypt -DPROJECT_VERSION='"$(BCRYPT_VERSION)"'
CFLAGS += $(shell $(PKG_CONFIG) --cflags libcrypto)
MODLIBS += $(shell $(PKG_CONFIG) --libs libcrypto)
include $(NAVISERVER)/include/Makefile.module
