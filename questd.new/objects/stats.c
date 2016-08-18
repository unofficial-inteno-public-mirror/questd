#include "stats.h"

struct ubus_method stats_cpu_m[] = {
	UBUS_METHOD_NOARG("show", stats_cpu_show)
};
struct ubus_method stats_memory_m[] = {
	UBUS_METHOD_NOARG("show", stats_memory_show)
};
struct ubus_method stats_traffic_m[] = {
	UBUS_METHOD_NOARG("show", stats_traffic_show)
};
struct ubus_method stats_connections_m[] = {
	UBUS_METHOD_NOARG("show", stats_connections_show)
};

struct ubus_object stats_cpu = QUESTD_UBUS_OBJECT(
			UBUS_NAME_STATS_CPU, stats_cpu_m);
struct ubus_object stats_memory = QUESTD_UBUS_OBJECT(
			UBUS_NAME_STATS_MEMORY, stats_memory_m);
struct ubus_object stats_traffic = QUESTD_UBUS_OBJECT(
			UBUS_NAME_STATS_TRAFFIC, stats_traffic_m);
struct ubus_object stats_connections = QUESTD_UBUS_OBJECT(
			UBUS_NAME_STATS_CONNECTIONS, stats_connections_m);

struct ubus_object *stats_objects[] = {
	&stats_cpu,
	&stats_memory,
	&stats_traffic,
	&stats_connections
};


/* static functions declarations */
static void stats_cpu_data_to_blob(struct blob_buf *buf);
static void stats_memory_data_to_blob(struct blob_buf *buf);
static void stats_traffic_data_to_blob(struct blob_buf *buf);
static void stats_connections_data_to_blob(struct blob_buf *buf);


void add_stats_objects(struct ubus_context *ctx)
{
	/* populate the objects containig the actual data */
	stats_data_init();

	/* register objects to ubus */
	add_objects_generic(ctx, stats_objects, ARRAY_SIZE(stats_objects));
}


int stats_cpu_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	stats_cpu_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

int stats_memory_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	stats_memory_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

int stats_traffic_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	stats_traffic_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

int stats_connections_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf buf = {};

	UNUSED(msg);

	printf("Executing: obj.name = %s method = %s\n",
		obj->name, method);

	/* prepare the reply in buf */
	blob_buf_init(&buf, 0);
	stats_connections_data_to_blob(&buf);

	/* send the reply to ubus */
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}


/* static functions definitions */
static void stats_cpu_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&stats_cpu_lock);

	pthread_mutex_unlock(&stats_cpu_lock);
}

static void stats_memory_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&stats_memory_lock);

	blobmsg_add_u32(buf, "total", stats_memory_data.total);
	blobmsg_add_u32(buf, "used", stats_memory_data.used);
	blobmsg_add_u32(buf, "free", stats_memory_data.free);
	blobmsg_add_u32(buf, "shared", stats_memory_data.shared);
	blobmsg_add_u32(buf, "buffers", stats_memory_data.buffers);

	pthread_mutex_unlock(&stats_memory_lock);
}

static void stats_traffic_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&stats_traffic_lock);

	pthread_mutex_unlock(&stats_traffic_lock);
}

static void stats_connections_data_to_blob(struct blob_buf *buf)
{
	UNUSED(buf);
	pthread_mutex_lock(&stats_connections_lock);

	blobmsg_add_u32(buf, "tcp_count", stats_connections_data.tcp_count);
	blobmsg_add_u32(buf, "udp_count", stats_connections_data.udp_count);

	pthread_mutex_unlock(&stats_connections_lock);
}
