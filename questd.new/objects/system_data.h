#ifndef QUESTD_SYSTEM_DATA_H
#define QUESTD_SYSTEM_DATA_H

#include <pthread.h>
/* #include <uci.h> */

#include "common.h"

#define UCI_HW_DB_DIR "/lib/db/config"
#define UCI_HW_DB_NAME "hw"
#define UCI_HW_DB_SECTION "board"

/* data structures declarations */
struct system_info_data;
struct system_memory_data;
struct system_keys_data;
struct system_specs_data;

/* data structures definitions */
struct system_info_data {
	/* invariable members */
	char name[NAME_MAX]; /* Inteno */

	char hardware[NAME_MAX]; /* EG300 */
	char model[NAME_MAX]; /* EG300-WU21UDAC */
	char boardid[NAME_MAX]; /* EG300R0 */

	char serialno[NAME_MAX]; /* E3AC24H154052013 */
	char basemac[NAME_MAX]; /* 00:22:07:4B:9B:9A */

	char cfever[NAME_MAX]; /* 1.0.38-118.3-INT1.3 */
	char socmod[NAME_MAX]; /* 63268 */
	char socrev[NAME_MAX]; /* d0 */

	char firmware[NAME_MAX]; /* EG300-WU21U_INT3.8.0RC0-160725_0352 */
	char brcmver[NAME_MAX]; /* 4.16L.05 */
	char filesystem[NAME_MAX]; /* UBIFS */

	char kernel_name[NAME_MAX]; /* Linux */
	union {
		char kernel_release[NAME_MAX]; /* 3.4.11-rt19 */
		char kernel[NAME_MAX]; /* two names for the same data */
	};
	char kernel_version[NAME_MAX];
		/* #1 SMP PREEMPT Mon Jul 25 03:33:12 CEST 2016 */

	/* changeable members */
	char date[NAME_MAX];
	char uptime[NAME_MAX];
	long localtime;

	unsigned int procs;
	unsigned int cpu;
};

struct system_memory_data {
	/* changeable members */
	unsigned long total;
	unsigned long used;
	unsigned long free;
	unsigned long shared;
	unsigned long buffers;
};

struct system_keys_data {
	char auth[NAME_MAX];
	char des[NAME_MAX];
	char wpa[NAME_MAX];
};

struct system_specs_data {
	bool wifi;
	bool adsl;
	bool vdsl;
	bool voice;
	bool dect;
	int vports;
	int eports;
};

/* data objects */
extern struct system_info_data system_info_data;
extern struct system_memory_data system_memory_data;
extern struct system_keys_data system_keys_data;
extern struct system_specs_data system_specs_data;

/* data objects locks */
extern pthread_mutex_t system_info_lock;
extern pthread_mutex_t system_memory_lock;
extern pthread_mutex_t system_keys_lock;
extern pthread_mutex_t system_specs_lock;
/* use system_*_data only with system_*_data_lock taken*/

/* initialize all data objects */
void system_data_init(void);

/* initialize data object (called once) */
void system_info_init(void);
void system_memory_init(void);
void system_keys_init(void);
void system_specs_init(void);

/* update data objects (called repeatedly by the worker thread) */
void system_info_update(void);
void system_memory_update(void);
void system_keys_update(void);
void system_specs_update(void);

/* register update functions to worker thread */
extern void add_worker_job(void (*function)(void));

#endif /* QUESTD_SYSTEM_DATA_H */
