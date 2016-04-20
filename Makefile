CC		= gcc
CFLAGS		= -g -Wall 
LOCLIBS		= 
LIBS		= -luci -lubus -lubox -lpthread -lblobmsg_json

# IF BROADCOM
WLOBJS = broadcom.o
WLSRCS = broadcom.c
#

OBJS		= questd.o dumper.o port.o arping.o usb.o ndisc.o dslstats.o tools.o ${WLOBJS}
SRCS		= questd.c dumper.c port.c arping.c usb.c ndisc.c dslstats.c tools.c ${WLSRCS}
LIBSRCS		= 
ISRCS		= questd.h broadcom.h tools.h

all: questd ueventd uscriptd

questd: ${OBJS}
	${CC} ${LDFLAGS} ${LIBSRCS} -o questd ${OBJS} ${LIBS}

EOBJS		= eventd.o
ESRCS		= eventd.c

ueventd: ${EOBJS}
	${CC} ${LDFLAGS} -o ueventd ${EOBJS} ${LIBS}

SOBJS		= scriptd.o
SSRCS		= scriptd.c

uscriptd: ${SOBJS}
	${CC} ${LDFLAGS} -o uscriptd ${SOBJS} ${LIBS}

clean:
	rm -f questd ueventd uscriptd *.o

