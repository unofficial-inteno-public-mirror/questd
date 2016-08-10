#include <sys/utsname.h>
#include <sys/sysinfo.h>

#include <uci.h>

#include "system_data.h"


/* static functions declarations */
static void system_info_uptime(long seconds, char *buf);
static void system_info_hardware(void);
static void get_hardware(char *option, char *buf);
static void system_info_cpu(unsigned int *cpu);


void system_data_init(void)
{
	system_info_init();
	system_memory_init();
	system_keys_init();
	system_specs_init();

	/* register update functions to worker thread */
	add_worker_job(&system_info_update);
	add_worker_job(&system_memory_update);
	add_worker_job(&system_keys_update);
	add_worker_job(&system_specs_update);
}

/* init functions */
void system_info_init(void)
{
	struct utsname info;

	uname(&info);

	pthread_mutex_lock(&system_info_lock);
	strncpy(system_info_data.name, info.nodename, NAME_MAX);
	strncpy(system_info_data.kernel_name, info.sysname, NAME_MAX);
	strncpy(system_info_data.kernel_release, info.release, NAME_MAX);
	strncpy(system_info_data.kernel_version, info.version, NAME_MAX);

	system_info_hardware();

	pthread_mutex_unlock(&system_info_lock);

	system_info_update();
}

void system_memory_init(void)
{
	/* all data is updated in _update function */
	system_memory_update();
}

void system_keys_init(void)
{
	get_hardware("authKey", system_keys_data.auth);
	get_hardware("desKey", system_keys_data.des);
	get_hardware("wpaKey", system_keys_data.wpa);

	system_keys_update();
}

void system_specs_init(void)
{
	char buf[NAME_MAX];

	get_hardware("hasWifi", buf);
	if (buf[0] == '1')
		system_specs_data.wifi = true;

	get_hardware("hasAdsl", buf);
	if (buf[0] == '1')
		system_specs_data.adsl = true;

	get_hardware("hasVdsl", buf);
	if (buf[0] == '1')
		system_specs_data.vdsl = true;

	get_hardware("hasVoice", buf);
	if (buf[0] == '1')
		system_specs_data.voice = true;

	get_hardware("hasDect", buf);
	if (buf[0] == '1')
		system_specs_data.dect = true;

	if (system_specs_data.voice) {
		get_hardware("VoicePorts", buf);
		system_specs_data.vports = atoi(buf);
	}

	get_hardware("ethernetPorts", buf);
	system_specs_data.eports = atoi(buf);

	system_specs_update();
}


/* update functions */
void system_info_update(void)
{
	struct sysinfo info;

	sysinfo(&info);

	pthread_mutex_lock(&system_info_lock);

	/* uptime */
	system_info_uptime(info.uptime, system_info_data.uptime);
	/* localtime */
	time(&system_info_data.localtime);
	/* date */
	snprintf(system_info_data.date, NAME_MAX,
		ctime(&system_info_data.localtime));
	trim(system_info_data.date);

	/* procs */
	system_info_data.procs = info.procs;

	/* cpu */
	system_info_cpu(&system_info_data.cpu);

	pthread_mutex_unlock(&system_info_lock);
}

void system_memory_update(void)
{
	struct sysinfo info;

	sysinfo(&info);

	/* memory in kilobytes */
	system_memory_data.total = info.totalram >> 10;
	system_memory_data.free = info.freeram >> 10;
	system_memory_data.shared = info.sharedram >> 10;
	system_memory_data.buffers = info.bufferram >> 10;
	system_memory_data.used =
		system_memory_data.total - system_memory_data.free;

}

void system_keys_update(void)
{
}

void system_specs_update(void)
{
}


/* static functions definitions */
static void system_info_uptime(long seconds, char *buf)
{
	struct tm *uptime;

	uptime = gmtime(&seconds);

	/* adjust year: seconds is since 1970, tm_year is since 1900 */
	uptime->tm_year -= 70;
	if (uptime->tm_year < 0)
		uptime->tm_year = 0;

	if (uptime->tm_year)
		snprintf(buf, NAME_MAX, "%dy %dd %dh %dm %ds",
			uptime->tm_year, uptime->tm_yday,
			uptime->tm_hour, uptime->tm_min, uptime->tm_sec);
	else if (uptime->tm_yday)
		snprintf(buf, NAME_MAX, "%dd %dh %dm %ds", uptime->tm_yday,
			uptime->tm_hour, uptime->tm_min, uptime->tm_sec);
	else if (uptime->tm_hour)
		snprintf(buf, NAME_MAX, "%dh %dm %ds",
			uptime->tm_hour, uptime->tm_min, uptime->tm_sec);
	else if (uptime->tm_min)
		snprintf(buf, NAME_MAX, "%dm %ds",
			uptime->tm_min, uptime->tm_sec);
	else
		snprintf(buf, NAME_MAX, "%ds", uptime->tm_sec);
}

static void system_info_hardware(void)
{
	get_hardware("hardwareVersion", system_info_data.hardware);
	get_hardware("routerModel", system_info_data.model);
	get_hardware("boardId", system_info_data.boardid);

	get_hardware("serialNumber", system_info_data.serialno);
	get_hardware("BaseMacAddr", system_info_data.basemac);

	get_hardware("cfeVersion", system_info_data.cfever);
	get_hardware("socModel", system_info_data.socmod);
	get_hardware("socRevision", system_info_data.socrev);

	get_hardware("iopVersion", system_info_data.firmware);
	get_hardware("brcmVersion", system_info_data.brcmver);
	get_hardware("filesystem", system_info_data.filesystem);

}

static void get_hardware(char *option, char *buf)
{
	int rv;
	static struct uci_context *uci_ctx;
	struct uci_ptr ptr;

	if (!uci_ctx) {
		/* connect to uci */
		uci_ctx = uci_alloc_context();
		if (!uci_ctx)
			return;
		uci_set_confdir(uci_ctx, UCI_HW_DB_DIR);
		uci_load(uci_ctx, UCI_HW_DB_NAME, NULL);
	}

	ptr = (struct uci_ptr) {
		.package = UCI_HW_DB_NAME,
		.section = UCI_HW_DB_SECTION,
		.option = option
	};

	/* query uci */
	rv = uci_lookup_ptr(uci_ctx, &ptr, NULL, true);
	if (rv != UCI_OK || !(ptr.flags & UCI_LOOKUP_COMPLETE)
		|| !ptr.o || !ptr.o->v.string)
		return;

	snprintf(buf, NAME_MAX, "%s", ptr.o->v.string);
}


static void system_info_cpu(unsigned int *usage)
{
	int rv;
	unsigned int i;
	unsigned long long jiffies[16];
	unsigned long long idle, total = 0, idle_delta, total_delta;
	static unsigned long long idle_prev, total_prev;
	char line[1024], *ptr;
	FILE *file;

	file = fopen("/proc/stat", "r");
	if (!file)
		return;

	/* get the cpu aggregate statistics line */
	while (fgets(line, 1024, file))
		if (strstr(line, "cpu ") == line)
			break;
	fclose(file);

	trim(line);
	ptr = line + strlen("cpu ");
	memset(jiffies, 0, ARRAY_SIZE(jiffies) * sizeof(*jiffies));
	rv = sscanf(ptr,
	"%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu",
		&jiffies[0], &jiffies[1], &jiffies[2], &jiffies[3],
		&jiffies[4], &jiffies[5], &jiffies[6], &jiffies[7],
		&jiffies[8], &jiffies[9], &jiffies[10], &jiffies[11],
		&jiffies[12], &jiffies[13], &jiffies[14], &jiffies[15]);

	if (rv < 4)
		return;

	/* idle is the 4th column */
	idle = jiffies[3];
	for (i = 0; i < ARRAY_SIZE(jiffies); i++)
		total += jiffies[i];

	if (!idle_prev || !total_prev) {
		idle_prev = idle;
		total_prev = total;
		return;
	}

	/* calculate the delta values */
	idle_delta = idle - idle_prev;
	total_delta = total - total_prev;
	if (idle < idle_prev || total <= total_prev || total_delta < idle_delta)
		return;

	/* save idle and total current measurements as previous measurements */
	idle_prev = idle;
	total_prev = total;

	/* compute the usage as percentage */
	*usage = 100 - idle_delta * 100 / total_delta;
}
