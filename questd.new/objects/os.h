#ifndef QUESTD_OS_H
#define QUESTD_OS_H

#include "common.h"
#include "os_data.h"

/* ubus objects names */
#define UBUS_NAME_OS_FILESYSTEM		"router.os.filesystem"
#define UBUS_NAME_OS_PASSWORD		"router.os.password"
#define UBUS_NAME_OS_LOGS		"router.os.logs"

/* ubus methods */
struct ubus_method os_filesystem_m[];
struct ubus_method os_password_m[];
struct ubus_method os_logs_m[];

/* ubus objects */
struct ubus_object os_filesystem;
struct ubus_object os_password;
struct ubus_object os_logs;

/* ubus objects array */
struct ubus_object *os_objects[];

/* data objects */
struct list_head os_filesystem_list = LIST_HEAD_INIT(os_filesystem_list);
struct os_password_data os_password_data;
struct os_logs_data os_logs_data;

/* data objects locks */
pthread_mutex_t os_filesystem_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t os_password_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t os_logs_lock = PTHREAD_MUTEX_INITIALIZER;
/* use os_*_data only with os_*_data_lock taken*/

/* methods registered directly to ubus */
int os_filesystem_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int os_password_set(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);
int os_logs_show(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

/* register os objects to ubus */
void add_os_objects(struct ubus_context *ctx);

#endif /* QUESTD_OS_H */
