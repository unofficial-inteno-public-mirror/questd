#define _POSIX_C_SOURCE 2
#include <stdio.h>
#undef _POSIX_C_SOURCE

#include "os_data.h"


/* static functions declarations */
static void os_filesystem_get(struct list_head *head);


void os_data_init(void)
{
	os_filesystem_init();
	os_password_init();
	os_logs_init();

	/* register update functions to worker thread */
	add_worker_job(&os_filesystem_update);
	add_worker_job(&os_password_update);
	add_worker_job(&os_logs_update);
}

/* init functions */
void os_filesystem_init(void)
{

	pthread_mutex_lock(&os_filesystem_lock);

	os_filesystem_get(&os_filesystem_list);

	pthread_mutex_unlock(&os_filesystem_lock);

	os_filesystem_update();
}

void os_password_init(void)
{
	os_password_update();
}

void os_logs_init(void)
{
	os_filesystem_update();
}

/* update functions */
void os_filesystem_update(void)
{
	pthread_mutex_lock(&os_filesystem_lock);
	pthread_mutex_unlock(&os_filesystem_lock);
}

void os_password_update(void)
{
}

void os_logs_update(void)
{
}


/* done functions: called for cleanup */
void os_filesystem_done(void)
{
	struct os_filesystem_data *cursor, *next;

	UNUSED(cursor);
	UNUSED(next);
	/* clear the filesystem list */
	list_for_each_entry_safe(cursor, next, &os_filesystem_list, list) {
		list_del(&cursor->list);
		free(cursor);
	}

	/* reinitialize the list head */
	INIT_LIST_HEAD(&os_filesystem_list);
}


/* static functions definitions */
static void os_filesystem_get(struct list_head *head)
{
	int rv;
	struct os_filesystem_data *filesystem = NULL;
	char line[PATH_MAX], usage[8];
	FILE *file;

	file = popen("df", "r");
	if (!file)
		return;
	/* TODO: optimize: reduce the number of processes created here, 2
	* good solution: 1 extra process: replace popen with fork pipe dup exec
	* better solution: no extra process: replace popen with
	*	read /proc/mounts
	*	statvfs
	*/

	while (fgets(line, PATH_MAX, file)) {

		if (!filesystem)
			filesystem = malloc(sizeof(*filesystem));
		if (!filesystem)
			goto exit;

		trim(line);
		rv = sscanf(line, "%s %ld %ld %ld %7s %s", filesystem->name,
			&filesystem->blocks, &filesystem->used,
			&filesystem->available, usage, filesystem->mountpoint);
		if (rv != 6)
			continue;

		/* remove trailing % from usage, e.g. "42%" */
		/* while (!isdigit(usage[strlen(usage) - 1])) */
		while (usage[strlen(usage) - 1] == '%')
			usage[strlen(usage) - 1] = 0;
		filesystem->usage = atoi(usage);

		/* add filesystem to list */
		list_add_tail(&filesystem->list, head);
		filesystem = NULL;
	}

exit:
	pclose(file);
}
