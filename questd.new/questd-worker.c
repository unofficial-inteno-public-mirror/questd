#include "questd-worker.h"



void start_worker(void)
{
	pthread_t tid;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (!pthread_create(&tid, &attr, work, NULL))
		printf("pthread_create failed\n");
}

void *work(void *arg)
{
	printf("work()\n");
	while (1) {
		run_jobs();
		sleep(5);
	}
}

void run_jobs(void)
{
	struct list_head *ptr;
	struct worker_job *job;

	printf("run_jobs()\n");

	pthread_mutex_lock(&jobs_lock);
	list_for_each(ptr, &jobs) {
		job = list_entry(ptr, struct worker_job, list);
		if (job && job->function)
			job->function();
	}
	pthread_mutex_unlock(&jobs_lock);
}


void add_worker_job(void (*function)(void))
{
	struct worker_job *job = calloc(1, sizeof(struct worker_job));

	job->function = function;

	pthread_mutex_lock(&jobs_lock);
	list_add(&job->list, &jobs);
	pthread_mutex_unlock(&jobs_lock);
}
