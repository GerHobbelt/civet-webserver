# This Makefile is part of Mongoose web server project,
# https://github.com/valenok/mongoose
#
# This Makefile is GNU make compatible. You can get GNU Make from
# http://gnuwin32.sourceforge.net/packages/make.htm
#
# Example custom build:
# CFLAGS_EXTRA="-g -O0 -DNO_SSL_DL -DUSE_LUA -llua -lcrypto -lssl" make linux
#
# Flags are:
# -DHAVE_MD5              - use system md5 library (-2kb)
# -DNDEBUG                - strip off all debug code (-5kb)
# -DDEBUG                 - build debug version (very noisy) (+7kb)
# -DNO_CGI                - disable CGI support (-5kb)
# -DNO_SSL                - disable SSL functionality (-2kb)
# -DNO_SSL_DL             - link against system libssl library (-1kb)
# -DCONFIG_FILE=\"file\"  - use `file' as the default config file
# -DSSL_LIB=\"libssl.so.<version>\"   - use system versioned SSL shared object
# -DCRYPTO_LIB=\"libcrypto.so.<version>\" - use system versioned CRYPTO so
# -DUSE_LUA               - embed Lua in Mongoose (+100kb)

PROG = mongoose
EXE_SUFFIX =
CFLAGS = -std=c99 -O2 -W -Wall -pedantic -pthread -pipe -I. -I.. $(CFLAGS_EXTRA)
CFLAGS += -ldl -lm
VERSION = $(shell perl -lne \
            'print $$1 if /define\s+MONGOOSE_VERSION\s+"(\S+)"/' ../mongoose.c)

# The order in which files are listed is important
SOURCES = src/internal.h src/util.c src/string.c src/parse_date.c \
          src/options.c src/crypto.c src/auth.c src/win32.c src/unix.c \
          src/mg_printf.c src/ssl.c src/http_client.c \
          src/mongoose.c src/lua.c

TINY_SOURCES = ../mongoose.c main.c
LUA_SOURCES = $(TINY_SOURCES) sqlite3.c lsqlite3.c lua_5.2.1.c

SQLITE_FLAGS = -DTHREADSAFE=1 -DSQLITE_ENABLE_FTS3 \
               -DSQLITE_ENABLE_FTS3_PARENTHESIS
LUA_FLAGS = -DUSE_LUA -DUSE_LUA_SQLITE3 -DLUA_COMPAT_ALL
LUA_SQLITE_FLAGS = $(SQLITE_FLAGS) $(LUA_FLAGS)



all: $(PROG)

test:
	prove 00.t

../mongoose.c: ../mongoose.h Makefile $(SOURCES)
	cat $(SOURCES) | sed '/#include "internal.h"/d' > $@

unix_unit_test: $(LUA_SOURCES) Makefile ../test/unit_test.c
	$(CC) ../test/unit_test.c lua_5.2.1.c $(CFLAGS) -g -O0 -o t && ./t

# Make sure that the compiler flags come last in the compilation string.
# If not so, this can break some on some Linux distros which use
# "-Wl,--as-needed" turned on by default  in cc command.
# Also, this is turned in many other distros in static linkage builds.
$(PROG): $(TINY_SOURCES)
	$(CC) $(TINY_SOURCES) -o $@ $(CFLAGS)

tests:
	perl ../test/test.pl $(TEST)

clean:
	cd ../examples && $(MAKE) clean
	rm -rf *.o *.core $(PROG) *.obj *.so $(PROG).txt *.dSYM *.tgz \
	*.lib res.o res.RES *.dSYM *.zip *.pdb \
	*dmg* $(PROG)-* unix_unit_test
