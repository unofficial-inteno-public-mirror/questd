#ifndef QUESTD_SYSTEM_DATA_H
#define QUESTD_SYSTEM_DATA_H

#include <pthread.h>
/* #include <uci.h> */

#include "common.h"

#define UCI_HW_DB_DIR "/lib/db/config"
#define UCI_HW_DB_NAME "hw"
#define UCI_HW_DB_SECTION "board"

struct system_info_data;
struct system_memory_data;
struct system_keys_data;
struct system_specs_data;

struct system_info_data {
	/* invariable members */
	char name[STRLENMAX]; /* Inteno */

	char hardware[STRLENMAX]; /* EG300 */
	char model[STRLENMAX]; /* EG300-WU21UDAC */
	char boardid[STRLENMAX]; /* EG300R0 */

	char serialno[STRLENMAX]; /* E3AC24H154052013 */
	char basemac[STRLENMAX]; /* 00:22:07:4B:9B:9A */

	char cfever[STRLENMAX]; /* 1.0.38-118.3-INT1.3 */
	char socmod[STRLENMAX]; /* 63268 */
	char socrev[STRLENMAX]; /* d0 */

	char firmware[STRLENMAX]; /* EG300-WU21U_INT3.8.0RC0-160725_0352 */
	char brcmver[STRLENMAX]; /* 4.16L.05 */
	char filesystem[STRLENMAX]; /* UBIFS */

	char kernel_name[STRLENMAX]; /* Linux */
	union {
		char kernel_release[STRLENMAX]; /* 3.4.11-rt19 */
		char kernel[STRLENMAX]; /* two names for the same data */
	};
	char kernel_version[STRLENMAX];
		/* #1 SMP PREEMPT Mon Jul 25 03:33:12 CEST 2016 */

	/* changeable members */
	char date[STRLENMAX];
	char uptime[STRLENMAX];
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
	char auth[STRLENMAX];
	char des[STRLENMAX];
	char wpa[STRLENMAX];
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

extern struct system_info_data system_info_data;
extern struct system_memory_data system_memory_data;
extern struct system_keys_data system_keys_data;
extern struct system_specs_data system_specs_data;

extern pthread_mutex_t system_info_lock;
extern pthread_mutex_t system_memory_lock;
extern pthread_mutex_t system_keys_lock;
extern pthread_mutex_t system_specs_lock;
/* use system_*_data only with system_*_data_lock taken*/


void system_data_init(void);

void system_info_init(void);
void system_memory_init(void);
void system_keys_init(void);
void system_specs_init(void);

void system_info_update(void);
void system_memory_update(void);
void system_keys_update(void);
void system_specs_update(void);

extern void add_worker_job(void (*function)(void));

#endif /* QUESTD_SYSTEM_DATA_H */
