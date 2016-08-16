#ifndef QUESTD_COMMON_H
#define QUESTD_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <linux/limits.h>

#include <libubus.h>
#include <libubox/list.h>

/* ISO C 99 does not have typeof */
#if __STDC_VERSION__ <= 199901L
#define typeof __typeof__
#endif /* __STDC_VERSION__ <= 199901L */

#define UNUSED(x) \
	do { \
		if (x) { \
			; \
			; \
		} \
	} while (0)

#define QUESTD_UBUS_OBJECT(_name, _methods) \
	{ \
		.name = _name, \
		.type = &(struct ubus_object_type) \
			UBUS_OBJECT_TYPE(_name, _methods), \
		.methods = _methods, \
		.n_methods = ARRAY_SIZE(_methods) \
	}

#define BLOBMSG_ADD_STRING(_buf, _name, _data) \
	blobmsg_add_string(_buf, #_name, (_data)->_name ? (_data)->_name : "")

#ifndef NAME_MAX
#define NAME_MAX 255
#endif /* NAME_MAX */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif /* PATH_MAX */

/* register count objects from objects array to ubus context ctx */
void add_objects_generic(struct ubus_context *ctx,
			struct ubus_object **objects, int count);

/* remove white spaces from the start and end of string str */
void trim(char *str);

#endif /* QUESTD_COMMON_H */
