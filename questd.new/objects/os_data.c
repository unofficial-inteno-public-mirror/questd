#define _POSIX_C_SOURCE 2
#include <stdio.h>
#undef _POSIX_C_SOURCE

#include <shadow.h>
#include <crypt.h>
#include <sys/wait.h>

#include "os_data.h"


/* static functions declarations */
static void os_filesystem_get(struct list_head *head);
static void os_logs_get(struct list_head *head);
static inline struct os_filesystem_data *parse_filesystem_line(char *line);
static inline struct os_logs_data *parse_log_line(char *line);

static int os_password_check(char *user, char *password);
static int os_password_change(char *user, char *password);
static inline int os_password_change_parent(int pipefd[], pid_t pid,
						char *password);
static inline int os_password_change_child(int pipefd[], char *user);

void os_data_init(void)
{
	os_filesystem_init();
	/* os_logs_init(); */

	/* register update functions to worker thread */
	add_worker_job(&os_filesystem_update);
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

int os_password_init(struct os_password_data *password)
{
	/* check current password matching */
	if (!os_password_check(password->user, password->password))
		return UBUS_STATUS_PERMISSION_DENIED;

	/* change the password */
	return os_password_change(password->user, password->newpassword);
}

void os_logs_init(void)
{
	pthread_mutex_lock(&os_logs_lock);

	os_logs_get(&os_logs_list);

	pthread_mutex_unlock(&os_logs_lock);

	os_logs_update();
}

/* update functions */
void os_filesystem_update(void)
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

void os_logs_done(void)
{
	struct os_logs_data *cursor, *next;

	/* clear the logs list */
	list_for_each_entry_safe(cursor, next, &os_logs_list, list) {
		list_del(&cursor->list);
		free(cursor);
	}

	/* reinitialize the list head */
	INIT_LIST_HEAD(&os_logs_list);
}


/* static functions definitions */

/* store filesystem entries in the list */
static void os_filesystem_get(struct list_head *head)
{
	char line[PATH_MAX];
	struct os_filesystem_data *filesystem;
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

		filesystem = parse_filesystem_line(line);

		if (filesystem)
			list_add_tail(&filesystem->list, head);
	}

	pclose(file);
}

/* store log entries in the list */
static void os_logs_get(struct list_head *head)
{
	char line[PATH_MAX];
	struct os_logs_data *log;
	FILE *file;

	file = popen("logread -l 400", "r");
	if (!file)
		return;
	/*TODO: optimize: reduce the number of processes created here, 2
	* good solution: query directly the ubus object log,
	*	similar to logread.c
	*/

	while (fgets(line, PATH_MAX, file)) {

		log = parse_log_line(line);

		if (log)
			list_add_tail(&log->list, head);
	}

	pclose(file);
}

/* Filesystem           1K-blocks      Used Available Use% Mounted on */
/* rootfs                   49084     32672     16412  67% /          */
static inline struct os_filesystem_data *parse_filesystem_line(char *line)
{
	int rv;
	struct os_filesystem_data *filesystem;
	char usage[8];

	filesystem = calloc(1, sizeof(*filesystem));
	if (!filesystem)
		goto out;

	trim(line);

	/* read name, blocks, used, available and mountpoint */
	rv = sscanf(line, "%s %ld %ld %ld %7s %s", filesystem->name,
			&filesystem->blocks, &filesystem->used,
			&filesystem->available, usage, filesystem->mountpoint);
	if (rv != 6)
		goto out;

	/* read usage */
	/* remove trailing % from usage, e.g. "42%" */
	/* while (!isdigit(usage[strlen(usage) - 1])) */
	while (usage[strlen(usage) - 1] == '%')
		usage[strlen(usage) - 1] = 0;
	filesystem->usage = atoi(usage);

	return filesystem;

out:
	if (filesystem)
		free(filesystem);
	return NULL;
}

/* time                     priority      source  message */
/* Mon Jan  1 HH:MM:SS YYYY daemon.notice netifd: wan ... */
/* Mon Jan 11 HH:MM:SS YYYY daemon.notice netifd: wan ... */
static inline struct os_logs_data *parse_log_line(char *line)
{

	int rv;
	char tmp[7][NAME_MAX];
	struct os_logs_data *log;

	log = calloc(1, sizeof(*log));
	if (!log)
		goto out;

	trim(line);

	/* read time, priority and source */
	rv = sscanf(line, "%s %s %s %s %s %s %[^:]:", *(tmp),
			*(tmp + 1), *(tmp + 2), *(tmp + 3),
			*(tmp + 4), *(tmp + 5), *(tmp + 6));
	if (rv != 7)
		goto out;
	line += snprintf(log->time, NAME_MAX, "%s %s %s %s %s",
			*(tmp), *(tmp + 1), *(tmp + 2), *(tmp + 3), *(tmp + 4));
	line += snprintf(log->priority, NAME_MAX, "%s", *(tmp + 5));
	snprintf(log->source, NAME_MAX, "%s", *(tmp + 6));

	/* read message */
	line = strstr(line, log->source) + strlen(log->source);
	while (!isspace(*line))
		line++;
	while (isspace(*line))
		line++;
	strncpy(log->message, line, NAME_MAX);

	return log;

out:
	if (log)
		free(log);
	return NULL;
}

/* return true if password matches current password in shadow */
static int os_password_check(char *user, char *password)
{
	struct spwd *sp;
	char *hash;

	if (!user || !password || !strlen(user) || !strlen(password))
		goto permission_denied;

	sp = getspnam(user);
	if (!sp)
		goto permission_denied;

	hash = crypt(password, sp->sp_pwdp);
	if (!hash)
		goto permission_denied;

	if (strncmp(hash, sp->sp_pwdp, strlen(sp->sp_pwdp)))
		goto permission_denied;

	return true;

permission_denied:
	return false;
}

/* return UBUS_STATUS_OK if the password was changed */
static int os_password_change(char *user, char *password)
{
	pid_t pid;
	int pipefd[2]; /* [0] - read end, [1] - write end */

	/* check parameters */
	if (!user || !password || !strlen(user) || !strlen(password))
		goto permission_denied;

	/* check that passwd binary exists */
	if (access("/usr/bin/passwd", X_OK) != 0)
		goto permission_denied;

	/* create pipes */
	if (pipe(pipefd) == -1)
		goto out;

	/* TODO: make sure that fork() does not happen between reconnecting
	 * to ubus and setting close-on-exec flag on the new descriptor
	 */

	pid = fork();
	if (pid < 0)
		goto out_pipefd;

	if (pid == 0) {
		/* child process */
		return os_password_change_child(pipefd, user);
	}

	/* parent process */
	return os_password_change_parent(pipefd, pid, password);

permission_denied:
	return UBUS_STATUS_PERMISSION_DENIED;
out_pipefd:
	close(pipefd[0]);
	close(pipefd[1]);
out:
	return UBUS_STATUS_UNKNOWN_ERROR;
}


static inline int os_password_change_parent(int pipefd[], pid_t pid,
						char *password)
{
	int rv, status, len = strlen(password);

	close(pipefd[0]); /* close the read end */

	/* New password: */
	rv = write(pipefd[1], password, len);
	if (rv != len)
		goto out_pipefd;
	rv = write(pipefd[1], "\n", 1);
	if (rv != 1)
		goto out_pipefd;

	/* Retype password: */
	rv = write(pipefd[1], password, len);
	if (rv != len)
		goto out_pipefd;
	rv = write(pipefd[1], "\n", 1);
	if (rv != 1)
		goto out_pipefd;

	close(pipefd[1]);

	/* get return status from child process */
	rv = waitpid(pid, &status, 0);
	if (rv == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		goto out;

	return UBUS_STATUS_OK;
out_pipefd:
	close(pipefd[1]);
out:
	return UBUS_STATUS_UNKNOWN_ERROR;
}

static inline int os_password_change_child(int pipefd[], char *user)
{
	int devnull;

	/* stop parent-specific inherited stuff */
	uloop_done();
	close(pipefd[1]); /* close the write end */

	/* use pipefd[0] as stdin */
	dup2(pipefd[0], 0 /* STDIN_FILENO */);
	close(pipefd[0]);

	/* redirect stdout and stderr to /dev/null */
	devnull = open("/dev/null", O_WRONLY);
	if (devnull != -1) {
		dup2(devnull, 1 /* STDOUT_FILENO */);
		dup2(devnull, 2 /* STDERR_FILENO */);
		close(devnull);
	}

	chdir("/");

	execl("/usr/bin/passwd", "/usr/bin/passwd", user, NULL);

	/* only if exec failed */
	return 1;

}
