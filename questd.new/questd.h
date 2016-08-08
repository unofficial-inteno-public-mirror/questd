#ifndef QUESTD_H
#define QUESTD_H

#include <stdio.h>
#include <fcntl.h> /* fcntl */

#include <libubus.h>

#include <libubox/uloop.h>

#define UNUSED(x) \
	do { \
		if (x) { \
			; \
			; \
		} \
	} while (0)

/*
* functions headers
*/
void add_objects(void);


void parse_args(int argc, char *argv[]);
void init_ubus(void);

void ubus_connect_cb(struct ubus_context *ctx);

void done_ubus(void);
void done_uloop(void);

extern void add_system_objects(struct ubus_context *ctx);

#endif /* QUESTD_H */
