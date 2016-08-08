#ifndef QUESTD_COMMON_H
#define QUESTD_COMMON_H

#include <stdio.h>
#include <string.h> /* strlen, memmove */
#include <ctype.h> /* isspace */
#include <libubus.h>

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


#define BLOBMSG_ADD_STRING_NO_NULL(_buf, _name, _data) \
	blobmsg_add_string(_buf, #_name, _data._name ? _data._name : "")

#define STRLENMAX 64

void add_objects_generic(struct ubus_context *ctx,
			struct ubus_object **objects, int count);
void trim(char *str);

#endif /* QUESTD_COMMON_H */
