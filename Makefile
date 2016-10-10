CC		= gcc
CFLAGS		= -g -Wall $(QUESTD_CLFAGS)
LIBS		= -luci -lubus -lubox -lpthread -lblobmsg_json -lcrypt
LOCLIBS		= 
OBJS		= questd.o dumper.o port.o arping.o usb.o ndisc.o dsl.o tools.o broadcom.o uboot_env.o dropbear.o wps.o system.o net.o network.o wireless.o mediatek.o
SRCS		= questd.c dumper.c port.c arping.c usb.c ndisc.c dsl.c tools.c broadcom.c uboot_env.c dropbear.c wps.c system.c net.c network.c wireless.c mediatek.c
LIBSRCS		= 
ISRCS		= questd.h network.h port.h wireless.h dsl.h tools.h broadcom.h uboot_env.h

all: questd wificontrol netcheck

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

WOBJS		= wificontrol.o arping.o tools.o
WSRCS		= wificontrol.c arping.c tools.c

wificontrol: ${WOBJS}
	${CC} ${LDFLAGS} -o wificontrol ${WOBJS} -lpthread

NOBJS		= netcheck.o arping.o
NSRCS		= netcheck.c arping.c

netcheck: ${NOBJS}
	${CC} ${LDFLAGS} -o netcheck ${NOBJS} -luci -ljson-c

clean:
	rm -f questd ueventd uscriptd wificontrol netcheck *.o

