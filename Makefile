ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  bcrypt.so

#
# Objects to build.
#
MODOBJS     = src/library.o src/bcrypt/bcrypt.o

#MODLIBS  +=

CFLAGS += -DUSE_NAVISERVER

include  $(NAVISERVER)/include/Makefile.module