#ifndef QUESTD_OS_DATA_H
#define QUESTD_OS_DATA_H

#include <pthread.h>

#include "common.h"

/* data structures declarations */
struct os_filesystem_data;
struct os_password_data;
struct os_logs_data;

/* data structures definitions */
struct os_filesystem_data {
	struct list_head list;

	char name[NAME_MAX];
	char mountpoint[PATH_MAX];
	unsigned long blocks;
	unsigned long used;
	unsigned long available;
	int usage;
};

struct os_password_data {
	char *user;
	char *password;
	char *newpassword;
};

struct os_logs_data {
	struct list_head list;

	char time[NAME_MAX];
	char priority[NAME_MAX];
	char source[NAME_MAX];
	char message[NAME_MAX];
};

/* data objects */
extern struct list_head os_filesystem_list;
extern struct list_head os_logs_list;

/* data objects locks */
extern pthread_mutex_t os_filesystem_lock;
extern pthread_mutex_t os_logs_lock;
/* use system_*_data only with system_*_data_lock taken*/

/* initialize all data objects */
void os_data_init(void);

/* initialize data object (called once) */
void os_filesystem_init(void);
int os_password_init(struct os_password_data *password);
void os_logs_init(void);

/* update data objects (called repeatedly by the worker thread) */
void os_filesystem_update(void);
void os_password_update(void);
void os_logs_update(void);

/* cleanup data */
void os_filesystem_done(void);
void os_logs_done(void);

/* register update functions to worker thread */
extern void add_worker_job(void (*function)(void));

#endif /* QUESTD_SYSTEM_DATA_H */
