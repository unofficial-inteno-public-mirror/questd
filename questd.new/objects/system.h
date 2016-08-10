#ifndef QUESTD_SYSTEM_H
#define QUESTD_SYSTEM_H

#include "common.h"
#include "system_data.h"

/* ubus object names */
#define UBUS_NAME_SYSTEM_INFO		"router.system.info"
#define UBUS_NAME_SYSTEM_MEMORY		"router.system.memory"
#define UBUS_NAME_SYSTEM_KEYS		"router.system.keys"
#define UBUS_NAME_SYSTEM_SPECS		"router.system.specs"

/* ubus methods */
struct ubus_method system_info_m[];
struct ubus_method system_memory_m[];
struct ubus_method system_keys_m[];
struct ubus_method system_specs_m[];

/* ubus objects */
struct ubus_object system_info;
struct ubus_object system_memory;
struct ubus_object system_keys;
struct ubus_object system_specs;

/* ubus objects array */
struct ubus_object *system_objects[];

/* data objects */
struct system_info_data system_info_data;
struct system_memory_data system_memory_data;
struct system_keys_data system_keys_data;
struct system_specs_data system_specs_data;

/* data objects locks */
pthread_mutex_t system_info_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t system_memory_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t system_keys_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t system_specs_lock = PTHREAD_MUTEX_INITIALIZER;
/* use system_*_data only with system_*_data_lock taken*/

/* methods registered directly to ubus */
int system_info_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int system_memory_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int system_keys_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int system_specs_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

/* register system objects to ubus */
void add_system_objects(struct ubus_context *ctx);

#endif /* QUESTD_SYSTEM_H */
