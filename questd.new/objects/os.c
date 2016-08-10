#include "os.h"

struct ubus_method os_filesystem_m[] = {
	UBUS_METHOD_NOARG("show", os_filesystem_show)
};
struct ubus_method os_password_m[] = {
	UBUS_METHOD_NOARG("set", os_password_set)
};
struct ubus_method os_logs_m[] = {
	UBUS_METHOD_NOARG("show", os_logs_show)
};

struct ubus_object os_filesystem = QUESTD_UBUS_OBJECT(UBUS_NAME_OS_FILESYSTEM,
							os_filesystem_m);
struct ubus_object os_password = QUESTD_UBUS_OBJECT(UBUS_NAME_OS_PASSWORD,
							os_password_m);
struct ubus_object os_logs = QUESTD_UBUS_OBJECT(UBUS_NAME_OS_LOGS,
							os_logs_m);

struct ubus_object *os_objects[] = {
	&os_filesystem,
	&os_password,
	&os_logs
};


/* static functions declarations */
static void os_filesystem_data_to_blob(struct blob_buf *buf);


void add_os_objects(struct ubus_context *ctx)
{
	/* populate the objects containig the actual data */
	os_data_init();

	/* register objects to ubus */
	add_objects_generic(ctx, os_objects, ARRAY_SIZE(os_objects));
}


int os_filesystem_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* gather data */
	os_filesystem_init();

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	os_filesystem_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	/* clean buffers */
	os_filesystem_done();

	return 0;
}

int os_password_set(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	UNUSED(ctx);
	UNUSED(obj);
	UNUSED(req);
	UNUSED(method);
	UNUSED(msg);

	return 0;
}

int os_logs_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	UNUSED(ctx);
	UNUSED(obj);
	UNUSED(req);
	UNUSED(method);
	UNUSED(msg);

	return 0;
}


/* static functions definitions */
static void os_filesystem_data_to_blob(struct blob_buf *buf)
{
	struct os_filesystem_data *filesystem;
	void *table;
	/* void *array; */

	pthread_mutex_lock(&os_filesystem_lock);

	/* array = blobmsg_open_array(buf, "filesystem"); */

	list_for_each_entry(filesystem, &os_filesystem_list, list) {

		table = blobmsg_open_table(buf,
			filesystem->name ? filesystem->name : "");

		BLOBMSG_ADD_STRING(buf, name, filesystem);
		BLOBMSG_ADD_STRING(buf, mountpoint, filesystem);
		blobmsg_add_u64(buf, "1kblocks", filesystem->blocks);
		blobmsg_add_u64(buf, "used", filesystem->used);
		blobmsg_add_u64(buf, "available", filesystem->available);
		blobmsg_add_u32(buf, "usage", filesystem->usage);

		blobmsg_close_table(buf, table);
	}

	/* blobmsg_close_array(buf, array); */

	pthread_mutex_unlock(&os_filesystem_lock);
}
