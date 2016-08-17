#ifndef QUESTD_STATS_H
#define QUESTD_STAST_H

#include "common.h"
#include "stats_data.h"

/* ubus object names */
#define UBUS_NAME_STATS_CPU		"router.stats.cpu"
#define UBUS_NAME_STATS_MEMORY		"router.stats.memory"
#define UBUS_NAME_STATS_TRAFFIC		"router.stats.traffic"
#define UBUS_NAME_STATS_CONNECTIONS	"router.stats.connections"

/* ubus methods */
struct ubus_method stats_cpu_m[];
struct ubus_method stats_memory_m[];
struct ubus_method stats_traffic_m[];
struct ubus_method stats_connections_m[];

/* ubus objects */
struct ubus_object stats_cpu;
struct ubus_object stats_memory;
struct ubus_object stats_traffic;
struct ubus_object stats_connections;

/* ubus objects array */
struct ubus_object *stats_objects[];

/* data objects */
struct stats_cpu_data stats_cpu_data;
struct stats_memory_data stats_memory_data;
struct stats_traffic_data stats_traffic_data;
struct stats_connections_data stats_connections_data;

/* data objects locks */
pthread_mutex_t stats_cpu_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_memory_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_traffic_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_connections_lock = PTHREAD_MUTEX_INITIALIZER;
/* use stats_*_data only with stats_*_data_lock taken*/

/* methods registered directly to ubus */
int stats_cpu_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int stats_memory_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int stats_traffic_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int stats_connections_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

/* register stats objects to ubus */
void add_stats_objects(struct ubus_context *ctx);

#endif /* QUESTD_STATS_H */
