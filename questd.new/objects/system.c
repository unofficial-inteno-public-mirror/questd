#include "system.h"

struct ubus_method system_info_m[] = {
	UBUS_METHOD_NOARG("show", system_info_show)
};
struct ubus_method system_memory_m[] = {
	UBUS_METHOD_NOARG("show", system_memory_show)
};
struct ubus_method system_keys_m[] = {
	UBUS_METHOD_NOARG("show", system_keys_show)
};
struct ubus_method system_specs_m[] = {
	UBUS_METHOD_NOARG("show", system_specs_show)
};

struct ubus_object system_info = QUESTD_UBUS_OBJECT(UBUS_NAME_SYSTEM_INFO,
							system_info_m);
struct ubus_object system_memory = QUESTD_UBUS_OBJECT(UBUS_NAME_SYSTEM_MEMORY,
							system_memory_m);
struct ubus_object system_keys = QUESTD_UBUS_OBJECT(UBUS_NAME_SYSTEM_KEYS,
							system_keys_m);
struct ubus_object system_specs = QUESTD_UBUS_OBJECT(UBUS_NAME_SYSTEM_SPECS,
							system_specs_m);

struct ubus_object *system_objects[] = {
	&system_info,
	&system_memory,
	&system_keys,
	&system_specs
};


/* static functions declarations */
static void system_info_data_to_blob(struct blob_buf *buf);
static void system_memory_data_to_blob(struct blob_buf *buf);
static void system_keys_data_to_blob(struct blob_buf *buf);
static void system_specs_data_to_blob(struct blob_buf *buf);


void add_system_objects(struct ubus_context *ctx)
{
	/* populate the objects containig the actual data */
	system_data_init();

	/* register objects to ubus */
	add_objects_generic(ctx, system_objects, ARRAY_SIZE(system_objects));
}


int system_info_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	system_info_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

int system_memory_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	system_memory_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

int system_keys_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	system_keys_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

int system_specs_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	system_specs_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}


/* static functions definitions */
static void system_info_data_to_blob(struct blob_buf *buf)
{
	/* struct system_info_data *data = &system_info_data; */

	pthread_mutex_lock(&system_info_lock);

	BLOBMSG_ADD_STRING(buf, name, &system_info_data);

	BLOBMSG_ADD_STRING(buf, hardware, &system_info_data);
	BLOBMSG_ADD_STRING(buf, model, &system_info_data);
	BLOBMSG_ADD_STRING(buf, boardid, &system_info_data);

	BLOBMSG_ADD_STRING(buf, serialno, &system_info_data);
	BLOBMSG_ADD_STRING(buf, basemac, &system_info_data);

	BLOBMSG_ADD_STRING(buf, cfever, &system_info_data);
	BLOBMSG_ADD_STRING(buf, socmod, &system_info_data);
	BLOBMSG_ADD_STRING(buf, socrev, &system_info_data);

	BLOBMSG_ADD_STRING(buf, firmware, &system_info_data);
	BLOBMSG_ADD_STRING(buf, brcmver, &system_info_data);
	BLOBMSG_ADD_STRING(buf, filesystem, &system_info_data);

	BLOBMSG_ADD_STRING(buf, kernel_name, &system_info_data);
	BLOBMSG_ADD_STRING(buf, kernel_release, &system_info_data);
	BLOBMSG_ADD_STRING(buf, kernel, &system_info_data);
	BLOBMSG_ADD_STRING(buf, kernel_version, &system_info_data);

	BLOBMSG_ADD_STRING(buf, date, &system_info_data);
	BLOBMSG_ADD_STRING(buf, uptime, &system_info_data);
	blobmsg_add_u64(buf, "localtime", system_info_data.localtime);

	blobmsg_add_u32(buf, "procs", system_info_data.procs);
	blobmsg_add_u32(buf, "cpu", system_info_data.cpu);

	pthread_mutex_unlock(&system_info_lock);
}

static void system_memory_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&system_memory_lock);

	blobmsg_add_u32(buf, "total", system_memory_data.total);
	blobmsg_add_u32(buf, "used", system_memory_data.used);
	blobmsg_add_u32(buf, "free", system_memory_data.free);
	blobmsg_add_u32(buf, "shared", system_memory_data.shared);
	blobmsg_add_u32(buf, "buffers", system_memory_data.buffers);

	pthread_mutex_unlock(&system_memory_lock);
}

static void system_keys_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&system_keys_lock);

	BLOBMSG_ADD_STRING(buf, auth, &system_keys_data);
	BLOBMSG_ADD_STRING(buf, des, &system_keys_data);
	BLOBMSG_ADD_STRING(buf, wpa, &system_keys_data);

	pthread_mutex_unlock(&system_keys_lock);
}

static void system_specs_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&system_specs_lock);

	blobmsg_add_u8(buf, "wifi", system_specs_data.wifi);
	blobmsg_add_u8(buf, "adsl", system_specs_data.adsl);
	blobmsg_add_u8(buf, "vdsl", system_specs_data.vdsl);
	blobmsg_add_u8(buf, "voice", system_specs_data.voice);
	blobmsg_add_u8(buf, "dect", system_specs_data.dect);
	blobmsg_add_u32(buf, "vports", system_specs_data.vports);
	blobmsg_add_u32(buf, "eports", system_specs_data.eports);

	pthread_mutex_unlock(&system_specs_lock);
}
