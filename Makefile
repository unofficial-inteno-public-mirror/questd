CC		= gcc
CFLAGS		= -g -Wall $(QUESTD_CFLAGS)
LIBS		= -luci -lubus -lubox -lpthread -lblobmsg_json
LOCLIBS		= 
OBJS		= questd.o dumper.o port.o arping.o usb.o ndisc.o dslstats.o tools.o broadcom.o uboot_env.o
SRCS		= questd.c dumper.c port.c arping.c usb.c ndisc.c dslstats.c tools.c broadcom.c uboot_env.c
LIBSRCS		= 
ISRCS		= questd.h tools.h broadcom.h

all: questd ueventd uscriptd

questd: ${OBJS}
	${CC} ${LDFLAGS} -o questd ${OBJS} ${LIBS}

EOBJS		= eventd.o
ESRCS		= eventd.c

ueventd: ${EOBJS}
	${CC} ${LDFLAGS} -o ueventd ${EOBJS} ${LIBS}

SOBJS		= scriptd.o tools.o
SSRCS		= scriptd.c tools.c

uscriptd: ${SOBJS}
	${CC} ${LDFLAGS} -o uscriptd ${SOBJS} ${LIBS}

clean:
	rm -f questd ueventd uscriptd *.o

