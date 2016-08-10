#ifndef QUESTD_H
#define QUESTD_H

#include <stdio.h>
#include <fcntl.h>

#include <libubus.h>

#include <libubox/uloop.h>

#define UNUSED(x) \
	do { \
		if (x) { \
			; \
			; \
		} \
	} while (0)

extern void add_system_objects(struct ubus_context *ctx);

#endif /* QUESTD_H */
