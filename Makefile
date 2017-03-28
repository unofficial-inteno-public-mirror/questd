CC			= gcc
CFLAGS		= -g -Wall $(QUESTD_CFLAGS)
LIBS		= -luci -lubus -lubox -lpthread -lblobmsg_json -lcrypt
ifeq ($(QUESTD_TARGET),-DIOPSYS_MEDIATEK)
LIBS		+= -lsw -lnl-tiny
endif
LOCLIBS		= 
OBJS		= questd.o dumper.o port.o arping.o usb.o ndisc.o dsl.o tools.o broadcom.o uboot_env.o dropbear.o wps.o system.o net.o network.o wireless.o mediatek.o directory.o
SRCS		= questd.c dumper.c port.c arping.c usb.c ndisc.c dsl.c tools.c broadcom.c uboot_env.c dropbear.c wps.c system.c net.c network.c wireless.c mediatek.c directory.c
LIBSRCS		= 
ISRCS		= questd.h network.h port.h wireless.h dsl.h tools.h broadcom.h uboot_env.h

all: questd wificontrol netcheck graphd 

questd: ${OBJS}
	${CC} ${LDFLAGS} -o questd ${OBJS} ${LIBS}

WOBJS		= wificontrol.o arping.o tools.o
WSRCS		= wificontrol.c arping.c tools.c

wificontrol: ${WOBJS}
	${CC} ${LDFLAGS} -o wificontrol ${WOBJS} -lpthread -luci

NOBJS		= netcheck.o arping.o
NSRCS		= netcheck.c arping.c

netcheck: ${NOBJS}
	${CC} ${LDFLAGS} -o netcheck ${NOBJS} -luci -ljson-c

GOBJS		= graphd.o tools.o
GOSRC		= graphd.c tools.c

graphd: ${GOBJS}
	${CC} ${LDFLAGS} -o graphd ${GOBJS} ${LIBS} -ljson-c

clean:
	rm -f questd ueventd uscriptd wificontrol netcheck graphd *.o

