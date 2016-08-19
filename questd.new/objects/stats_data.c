#include <sys/sysinfo.h>

#include <uci.h>

#include "stats_data.h"


/* static functions declarations */
static void stats_connections_count(int *tcp_count, int *udp_count);


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
	int tcp_count = 0, udp_count = 0;

	stats_connections_count(&tcp_count, &udp_count);

	pthread_mutex_lock(&stats_connections_lock);
	stats_connections_data.tcp_count = tcp_count;
	stats_connections_data.udp_count = udp_count;
	pthread_mutex_unlock(&stats_connections_lock);
}

/* static functions */
static void stats_connections_count(int *tcp_count, int *udp_count)
{
	int rv;
	char line[512];
	char type[16], established[64], unreplied_udp[64], unreplied_tcp[64];
	FILE *file;

	file = fopen("/proc/net/ip_conntrack", "r");

	if (!file)
		return;

	while (fgets(line, sizeof(line), file)) {
		trim(line);
		/* tcp 6 86386 ESTABLISHED src=ip dst=ip sport=50209
		 * dport=445 src=ip dst=ip sport=445 dport=50209 [ASSURED]
		 * mark=0 use=2
		 */
		rv = sscanf(line, "%s %*s %*s %s %*s %*s %*s %s %s",
			type, established, unreplied_udp, unreplied_tcp);

		if (rv != 4)
			continue;

		if (strcmp(type, "udp") == 0 &&
				strcmp(unreplied_udp, "[UNREPLIED]") != 0)
			++(*udp_count);
		else if (strcmp(type, "tcp") == 0 &&
				strcmp(established, "ESTABLISHED") == 0 &&
				strcmp(unreplied_tcp, "[UNREPLIED]") != 0)
			++(*tcp_count);
	}
	fclose(file);
}
