#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <crypt.h>
#include <fcntl.h>

#include <uci.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <libubus.h>

#if IOPSYS_BROADCOM
#include "broadcom.h" // WILL NOT BE NEEDED LATER
#endif


