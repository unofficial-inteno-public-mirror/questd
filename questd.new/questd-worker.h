#ifndef QUESTD_WORKER_H
#define QUESTD_WORKER_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <libubox/list.h>

#define UNUSED(x) \
	do { \
		if (x) { \
			; \
			; \
		} \
	} while (0)


struct worker_job {
	void (*function)();
	struct list_head list;
};
struct list_head jobs = LIST_HEAD_INIT(jobs);
pthread_mutex_t jobs_lock = PTHREAD_MUTEX_INITIALIZER;
/* use jobs only with jobs_lock taken */


/*
* functions headers
*/
void start_worker(void);
void *work(void *arg);
void run_jobs(void);

/* void add_worker_job(worker_job_function function); */
void add_worker_job(void (*function) (void));



#endif /* QUESTD_WORKER_H */
