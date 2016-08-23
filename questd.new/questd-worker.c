#include "questd-worker.h"


/* static functions declarations */
static void *work(void *arg);
static void run_jobs(void);

/* start the worker thread */
void start_worker(void)
{
	pthread_t tid;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&tid, &attr, work, NULL))
		printf("pthread_create failed\n");
}

/* starting function for the worker thread */
static void *work(void *arg)
{
	while (1) {
		run_jobs();
		sleep(5);
	}
}

/* run all jobs in the list */
static void run_jobs(void)
{
	struct worker_job *job;

	pthread_mutex_lock(&jobs_lock);
	list_for_each_entry(job, &jobs, list)
		if (job && job->function)
			job->function();

	pthread_mutex_unlock(&jobs_lock);
}

static void work_interval()
{
	while (1) {
		NANOsleep/select/pthread_cond_timedwait;
		first_job.time;

		run all jobs from first_job to job.time< first_job.time + 200ms

		job.time+=interval
		insert job again in the queue in cronological order.
	}
}


/* add job to jobs list */
void add_worker_job(void (*function)(void))
{
	struct worker_job *job = calloc(1, sizeof(struct worker_job));

	job->function = function;

	pthread_mutex_lock(&jobs_lock);
	list_add(&job->list, &jobs);
	pthread_mutex_unlock(&jobs_lock);
}
void add_worker_job_interval(void (*function)(void), int interval)
{
	struct worker_job *job = calloc(1, sizeof(struct worker_job));

	job->function = function;
	job->interval = interval;
	job->time = now();

	pthread_mutex_lock(&jobs_lock);
	list_add(&job->list, &jobs); /* add in front of the queue */
	pthread_mutex_unlock(&jobs_lock);
}

/* delete job from jobs list */
void del_worker_job(void (*function)(void))
{
	struct worker_job *job, *next;

	pthread_mutex_lock(&jobs_lock);
	list_for_each_entry_safe(job, next, &jobs, list)
		if (job && job->function == function) {
			list_del(&job->list);
			break;
		}
	pthread_mutex_unlock(&jobs_lock);
}
