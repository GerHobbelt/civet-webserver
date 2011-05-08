MANAGERS=all

include $(RTEMS_MAKEFILE_PATH)/Makefile.inc
include $(RTEMS_CUSTOM)
include $(PROJECT_ROOT)/make/leaf.cfg

CFLAGS+=\
	-I. \
	-Werror \
	-DNO_POPEN=1 \
	-DNO_CGI=1 \
	-DUSE_POSIX_FEATURES=1

BASENAME=mongoose

OTHER_CLEAN_FILES=$(BASENAME).num $(BASENAME).ralf

LIB=lib$(BASENAME).a
PGM=$(BASENAME).exe
LIBOBJS=$(BASENAME).o


OBJS=$(LIBOBJS) rtems/_init.o

# Change MAIN to chat if you have SSL installed and
# want to try to get that working.
MAIN=main
ifeq ($(MAIN),chat)
# You need to install SSL for chat.
CFLAGS+=\
	-I. \
	-DPTHREAD_RWLOCK_INITIALIZER=0
OBJS+=examples/chat.o
else
CFLAGS+=\
	-DNO_SSL=1 \
	-DNO_SSI=1
OBJS+=main.o
endif

all: $(LIB) $(PGM)

$(LIB) : $(LIBOBJS)
	@$(AR) r $(LIB) $(LIBOBJS)

$(PGM) : $(OBJS)
	@$(make-exe)

install: $(LIB)
	@$(INSTALL_VARIANT) -m 644 mongoose.h $(PROJECT_INCLUDE)
	@$(INSTALL_VARIANT) -m 644 $(LIB) $(PROJECT_RELEASE)/lib

clean:
	@rm -f $(OBJS) $(LIB) $(PGM) $(OTHER_CLEAN_FILES) examples/chat.o

foo:
	@echo $(PROJECT_RELEASE)
	@echo $(PROJECT_INCLUDE)
