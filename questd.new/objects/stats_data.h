#ifndef QUESTD_STAS_DATA_H
#define QUESTD_STATS_DATA_H

#include <pthread.h>

#include "common.h"

/* data structures declarations */
struct stats_cpu_data;
struct stats_memory_data;
struct stats_traffic_data;
struct stats_connections_data;

/* data structures definitions */
struct stats_cpu_data {
};

struct stats_memory_data {
	unsigned long total;
	unsigned long used;
	unsigned long free;
	unsigned long shared;
	unsigned long buffers;
};

struct stats_traffic_data {
};

struct stats_connections_data {
	int tcp_count;
	int udp_count;
};

/* data objects */
extern struct stats_cpu_data stats_cpu_data;
extern struct stats_memory_data stats_memory_data;
extern struct stats_traffic_data stats_traffic_data;
extern struct stats_connections_data stats_connections_data;

/* data objects locks */
extern pthread_mutex_t stats_cpu_lock;
extern pthread_mutex_t stats_memory_lock;
extern pthread_mutex_t stats_traffic_lock;
extern pthread_mutex_t stats_connections_lock;
/* use stats_*_data only with stats_*_data_lock taken*/

/* initialize all data objects */
void stats_data_init(void);

/* initialize data object (called once) */
void stats_cpu_init(void);
void stats_memory_init(void);
void stats_traffic_init(void);
void stats_connections_init(void);

/* update data objects (called repeatedly by the worker thread) */
void stats_cpu_update(void);
void stats_memory_update(void);
void stats_traffic_update(void);
void stats_connections_update(void);

/* register update functions to worker thread */
extern void add_worker_job(void (*function)(void));

#endif /* QUESTD_STATSTATS_H */
