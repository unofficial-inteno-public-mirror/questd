#include <sys/sysinfo.h>

#include <uci.h>

#include "stats_data.h"


void stats_data_init(void)
{
	stats_cpu_init();
	stats_memory_init();
	stats_traffic_init();
	stats_connections_init();

	/* register update functions to worker thread */
	add_worker_job(&stats_cpu_update);
	add_worker_job(&stats_memory_update);
	add_worker_job(&stats_traffic_update);
	add_worker_job(&stats_connections_update);
}

/* init functions */
void stats_cpu_init(void)
{
	stats_cpu_update();
}

void stats_memory_init(void)
{
	stats_memory_update();
}

void stats_traffic_init(void)
{
	stats_traffic_update();
}

void stats_connections_init(void)
{
	stats_connections_update();
}


/* update functions */
void stats_cpu_update(void)
{
	pthread_mutex_lock(&stats_cpu_lock);

	pthread_mutex_unlock(&stats_cpu_lock);
}

void stats_memory_update(void)
{
	struct sysinfo info;

	sysinfo(&info);

	/* memory in kilobytes */
	stats_memory_data.total = info.totalram >> 10;
	stats_memory_data.free = info.freeram >> 10;
	stats_memory_data.shared = info.sharedram >> 10;
	stats_memory_data.buffers = info.bufferram >> 10;
	stats_memory_data.used =
		stats_memory_data.total - stats_memory_data.free;
}

void stats_traffic_update(void)
{
}

void stats_connections_update(void)
{
}
