CC		= gcc
CFLAGS		= -g -Wall 
LOCLIBS		= 
LIBS		= -luci -lubus -lubox -lpthread -lblobmsg_json
OBJS		= questd.o dumper.o port.o arping.o usb.o ndisc.o dslstats.o tools.o
SRCS		= questd.c dumper.c port.c arping.c usb.c ndisc.c dslstats.c tools.c
LIBSRCS		= 
ISRCS		= questd.h

all: questd ueventd uscriptd

questd: ${OBJS}
	${CC} ${LDFLAGS} ${LIBSRCS} -o questd ${OBJS} ${LIBS}

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

