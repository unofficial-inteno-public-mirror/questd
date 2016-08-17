#include "common.h"


void add_objects_generic(struct ubus_context *ctx,
			struct ubus_object **objects, int count)
{
	int i;
	struct ubus_object *obj;

	for (i = 0; i < count; i++) {
		obj = objects[i];
		if (ubus_add_object(ctx, obj) != 0)
			printf("Failed to add object %s\n", obj->name);
		else
			printf("Registered object %s\n", obj->name);
	}
}

void trim(char *str)
{
	int i;

	if (!str)
		return;

	/* trim at the end */
	i = strlen(str);
	while (isspace(str[i - 1]))
		i--;
	str[i] = 0;

	/* trim at the start */
	i = 0;
	while (isspace(str[i]))
		i++;
	memmove(str, str + i, strlen(str) - i);
}
