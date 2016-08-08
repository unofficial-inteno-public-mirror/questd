CC		= gcc
#UBUS_INCLUDE	= "/home/alex/git/iopsys/staging_dir/target-mips_mips32_uClibc-0.9.33.2/usr/include/"
#UBUS_LIBS	= "/home/alex/git/iopsys/staging_dir/target-mips_mips32_uClibc-0.9.33.2/usr/lib/"
LIBS 		= -lubus -lubox -luci -lpthread
CFLAGS		= -std=c99 -Wall -Wextra -Wno-missing-field-initializers -I$(UBUS_INCLUDE) -pedantic -Werror -g $(LIBS) #-Wunused

LIBSOURCES		= $(wildcard objects/*.c)
#OBJECTS		= $(patsubst %c, %o, $(SOURCES))

default: codingstyle libobject.so questd

libobject.so:
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(LIBSOURCES)

questd:
	$(CC) $(CCFLAGS) -o $@ $(LIBS) questd.c questd-worker.c libobject.so

codingstyle:
	checkpatch.pl -no-tree -q -f *.[ch] objects/*

run:
	./questd && echo SUCCESS || echo FAILED

clean:
	rm -frv questd *.o lib*.so
