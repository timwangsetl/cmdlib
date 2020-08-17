include ../../Rule.mk
CFLAGS += -MMD -Os -Wall -s 
BIN = console

CFLAGS += -DIMP=\"$(IMP)\" -DWMP=\"$(WMP)\" -DPNUM=$(PNUM) -DGNUM=$(GNUM) -DXPORT=$(XPORT) -DMODULE=\"$(SYSNAME)\"
INCLUDES +=  -I../bcmutils -I../nvram  -I../utelnetd-0.1.2

CFLAGS += -DFVERSION=\"$(FVERSION)\"  -D$(SYSNAME) -DSYSNAME=\"$(SYSNAME)\" -DPOE=$(POE) -DPoE_NUM=$(POENUM) -D$(PROJECT_NAME)


LIBS = -L../bcmutils -lbcmutils -L../nvram -lnvram -lm  $(LIBNewPATH)

SRCS = $(wildcard *.c)

OBJS = $(SRCS:.c=.o)

all: $(BIN)

console: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) $(LIBS) -o  $@ 
	@echo "make $@ finished on `date`"

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

sinclude $(OBJS:.o=.d)

install:
	$(STRIP) $(BIN)
	cp -a $(BIN) ../../target/usr/sbin/console
	ln -fs /tmp/debug ../../target/www 

clean:
	rm -f $(BIN) *.o *.d

