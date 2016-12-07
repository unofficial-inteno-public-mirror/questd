/*
 * system -- provides router.system object of questd
 *
 * Copyright (C) 2012-2013 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: sukru.senli@inteno.se
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <crypt.h>
#include <shadow.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <libubox/blobmsg.h>
#include <libubus.h>

#include "system.h"
#include "tools.h"

enum {
	P_USER,
	P_PASSWORD,
	P_CURPASSWORD,
	__P_MAX
};

static const struct blobmsg_policy password_policy[__P_MAX] = {
	[P_USER]     = { .name = "user",     .type = BLOBMSG_TYPE_STRING },
	[P_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[P_CURPASSWORD] = { .name = "curpass", .type = BLOBMSG_TYPE_STRING }
};

enum {
	BANK,
	__BANK_MAX
};

static const struct blobmsg_policy bank_policy[__BANK_MAX] = {
	[BANK]     = { .name = "bank",     .type = BLOBMSG_TYPE_INT32 },
};

static struct blob_buf bb;

static Router router;
static Memory memory;
static Key keys;
static Spec spec;

static jiffy_counts_t cur_jif = {0};
static jiffy_counts_t prev_jif = {0};

void collect_system_info(void) {
	dump_keys(&keys);
	dump_specs(&spec);
	dump_static_router_info(&router);
	dump_hostname(&router);
}

void get_cpu_usage(int p) {
	if (p == 0)
		get_jif_val(&prev_jif);
	else
		get_jif_val(&cur_jif);
}

void calculate_cpu_usage(void) {
	dump_cpuinfo(&router, &prev_jif, &cur_jif);
}

static int
errno_status(void)
{
	switch (errno)
	{
	case EACCES:
		return UBUS_STATUS_PERMISSION_DENIED;

	case ENOTDIR:
		return UBUS_STATUS_INVALID_ARGUMENT;

	case ENOENT:
		return UBUS_STATUS_NOT_FOUND;

	case EINVAL:
		return UBUS_STATUS_INVALID_ARGUMENT;

	default:
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
}

static int
quest_password_set(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	pid_t pid;
	int fd, fds[2];
	char *hash;
	struct spwd *sp;
	struct stat s;
	struct blob_attr *tb[__P_MAX];

	blobmsg_parse(password_policy, __P_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[P_USER] || !tb[P_PASSWORD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if(tb[P_CURPASSWORD])
	{
		if (!(sp = getspnam(blobmsg_data(tb[P_USER]))))
			return UBUS_STATUS_PERMISSION_DENIED;

		hash = (char*) crypt(blobmsg_data(tb[P_CURPASSWORD]), sp->sp_pwdp);

		if(strcmp(hash, sp->sp_pwdp))
			return UBUS_STATUS_PERMISSION_DENIED;
	} else
		return UBUS_STATUS_PERMISSION_DENIED;

	if (stat("/usr/bin/passwd", &s))
		return UBUS_STATUS_NOT_FOUND;

	if (!(s.st_mode & S_IXUSR))
		return UBUS_STATUS_PERMISSION_DENIED;

	if (pipe(fds))
		return errno_status();

	switch ((pid = fork()))
	{
	case -1:
		close(fds[0]);
		close(fds[1]);
		return errno_status();

	case 0:
		uloop_done();

		dup2(fds[0], 0);
		close(fds[0]);
		close(fds[1]);

		if ((fd = open("/dev/null", O_RDWR)) > -1)
		{
			dup2(fd, 1);
			dup2(fd, 2);
			close(fd);
		}

		chdir("/");

		if (execl("/usr/bin/passwd", "/usr/bin/passwd",
		          blobmsg_data(tb[P_USER]), NULL))
			return errno_status();

	default:
		close(fds[0]);

		write(fds[1], blobmsg_data(tb[P_PASSWORD]),
		              blobmsg_data_len(tb[P_PASSWORD]) - 1);
		write(fds[1], "\n", 1);

		usleep(100 * 1000);

		write(fds[1], blobmsg_data(tb[P_PASSWORD]),
		              blobmsg_data_len(tb[P_PASSWORD]) - 1);
		write(fds[1], "\n", 1);

		close(fds[1]);

		waitpid(pid, NULL, 0);

		return 0;
	}
}

static int
quest_router_logread(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *a, *t;
	FILE *log;
	char line[512];
	char dayofweek[8];
	char month[8];
	int dayofmonth;
	char hour[16];
	int year;
	char id[32];
	char source[32];
	char time[64];

	struct stat s;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "logs");
	if (!stat("/log/messages", &s)) {
		if ((log = popen("tail -n 400 /log/messages 2>/dev/null", "r"))) {
			while(fgets(line, sizeof(line), log) != NULL)
			{
				remove_newline(line);
				if (sscanf(line, "%s %d %s %s %s:", month, &dayofmonth, hour, id, source)) {
					sprintf(time, "%s %d %s", month, dayofmonth, hour);
					source[strlen(source)-1] = '\0';
					t = blobmsg_open_table(&bb, "");
					blobmsg_add_string(&bb, "time", time);
					blobmsg_add_string(&bb, "id", id);
					blobmsg_add_string(&bb, "source", source);
					blobmsg_add_string(&bb, "message", line+(int)(strstr(line,source)-&line[0])+strlen(source)+2);
					blobmsg_close_table(&bb, t);
				}
			}
			pclose(log);
		}
	} else {
		if ((log = popen("logread -l 400", "r"))) {
			while(fgets(line, sizeof(line), log) != NULL)
			{
				remove_newline(line);
				if (sscanf(line, "%s %s %d %s %d %s %s:", dayofweek, month, &dayofmonth, hour, &year, id, source)) {
					sprintf(time, "%s %s %d %s %d", dayofweek, month, dayofmonth, hour, year);
					source[strlen(source)-1] = '\0';
					t = blobmsg_open_table(&bb, "");
					blobmsg_add_string(&bb, "time", time);
					blobmsg_add_string(&bb, "id", id);
					blobmsg_add_string(&bb, "source", source);
					blobmsg_add_string(&bb, "message", line+(int)(strstr(line,source)-&line[0])+strlen(source)+2);
					blobmsg_close_table(&bb, t);
				}
			}
			pclose(log);
		}
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static int
quest_router_processes(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *top;
	char line[1024];
	void *f, *l, *t;
	int pid, ppid, vsz;
	char user[64];
	char stat[64];
	char vszp[8];
	char cpup[8];
	char command[128];

	blob_buf_init(&bb, 0);

	f = blobmsg_open_array(&bb, "fields");
	blobmsg_add_string(&bb, "", "PID");
	blobmsg_add_string(&bb, "", "PPID");
	blobmsg_add_string(&bb, "", "USER");
	blobmsg_add_string(&bb, "", "STAT");
	blobmsg_add_string(&bb, "", "VSZ");
	blobmsg_add_string(&bb, "", "%VSZ");
	blobmsg_add_string(&bb, "", "%CPU");
	blobmsg_add_string(&bb, "", "COMMAND");
	blobmsg_close_array(&bb, f);

	if ((top = popen("top -bn1", "r"))) {
		l = blobmsg_open_array(&bb, "processes");
		while(fgets(line, sizeof(line), top) != NULL)
		{
			remove_newline(line);
			single_space(line);
			if(sscanf(line, "%d %d %s %s %d %s %s %s", &pid, &ppid, user, stat, &vsz, vszp, cpup, command)) {
				t = blobmsg_open_table(&bb, "");
				blobmsg_add_u32(&bb, "PID", pid);
				blobmsg_add_u32(&bb, "PPID", ppid);
				blobmsg_add_string(&bb, "USER", user);
				blobmsg_add_string(&bb, "STAT", stat);
				blobmsg_add_u32(&bb, "VSZ", vsz);
				blobmsg_add_string(&bb, "%VSZ", vszp);
				blobmsg_add_string(&bb, "%CPU", cpup);
				blobmsg_add_string(&bb, "COMMAND", command);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(top);
		blobmsg_close_array(&bb, l);
	}

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

int
quest_router_info(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *t, *m, *k, *s;
	dump_sysinfo(&router, &memory);

	blob_buf_init(&bb, 0);

	t = blobmsg_open_table(&bb, "system");
	blobmsg_add_string(&bb, "name", router.name);
	blobmsg_add_string(&bb, "hardware", router.hardware);
	blobmsg_add_string(&bb, "model", router.model);
	blobmsg_add_string(&bb, "boardid", router.boardid);
	blobmsg_add_string(&bb, "firmware", router.firmware);
	blobmsg_add_string(&bb, "brcmver", router.brcmver);
	blobmsg_add_string(&bb, "filesystem", router.filesystem);
	blobmsg_add_string(&bb, "socmod", router.socmod);
	blobmsg_add_string(&bb, "socrev", router.socrev);
	blobmsg_add_string(&bb, "cfever", router.cfever);
	blobmsg_add_string(&bb, "kernel", router.kernel);
	blobmsg_add_string(&bb, "basemac", router.basemac);
	blobmsg_add_string(&bb, "serialno", router.serialno);
	blobmsg_add_u32(&bb, "localtime", router.localtime);
	blobmsg_add_string(&bb, "date", router.date);
	blobmsg_add_string(&bb, "uptime", router.uptime);
	blobmsg_add_u32(&bb, "procs", router.procs);
	blobmsg_add_u32(&bb, "cpu_per", router.cpu);
	blobmsg_close_table(&bb, t);

	m =blobmsg_open_table(&bb, "memoryKB");
	blobmsg_add_u64(&bb, "total", memory.total);
	blobmsg_add_u64(&bb, "used", memory.used);
	blobmsg_add_u64(&bb, "free", memory.free);
	blobmsg_add_u64(&bb, "shared", memory.shared);
	blobmsg_add_u64(&bb, "buffers", memory.buffers);
	blobmsg_close_table(&bb, m);

	k = blobmsg_open_table(&bb, "keys");
	blobmsg_add_string(&bb, "auth", keys.auth);
	blobmsg_add_string(&bb, "des", keys.des);
	blobmsg_add_string(&bb, "wpa", keys.wpa);
	blobmsg_close_table(&bb, k);

	s = blobmsg_open_table(&bb, "specs");
	blobmsg_add_u8(&bb, "wifi", spec.wifi);
	blobmsg_add_u8(&bb, "adsl", spec.adsl);
	blobmsg_add_u8(&bb, "vdsl", spec.vdsl);
	blobmsg_add_u8(&bb, "voice", spec.voice);
	blobmsg_add_u32(&bb, "voice_ports", spec.vports);
	blobmsg_add_u32(&bb, "eth_ports", spec.eports);
	blobmsg_close_table(&bb, s);

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

int
quest_router_filesystem(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *a, *t;
	FILE *df;
	char line[128];
	char name[64];
	char mounted_on[128];
	char use_per[5];
	int blocks, used, available;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "filesystem");
	if ((df = popen("df", "r"))) {
		while(fgets(line, sizeof(line), df) != NULL)
		{
			remove_newline(line);
			single_space(line);
			if (sscanf(line, "%s %d %d %d %s %s", name, &blocks, &used, &available, use_per, mounted_on) == 6) {
				use_per[strlen(use_per)-1] = '\0';
				t = blobmsg_open_table(&bb, "");
				blobmsg_add_string(&bb, "name", name);
				blobmsg_add_u32(&bb, "1kblocks", blocks);
				blobmsg_add_u32(&bb, "used", used);
				blobmsg_add_u32(&bb, "available", available);
				blobmsg_add_u32(&bb, "use_pre", atoi(use_per));
				blobmsg_add_string(&bb, "mounted_on", mounted_on);
				blobmsg_close_table(&bb, t);
			}
		}
		pclose(df);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

int
quest_memory_bank(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__BANK_MAX];
	int bank;
	char this_fw[64];
	char other_fw[64];
	char output[64];

	blobmsg_parse(bank_policy, __BANK_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[BANK]) {
		bank = blobmsg_get_u32(tb[BANK]);
		if (bank == 0 || bank == 1)
			runCmd("brcm_fw_tool set -u %d", bank);
		else
			return UBUS_STATUS_INVALID_ARGUMENT;
	} else {

		bank = atoi(chrCmd(output, 64, "cat /proc/nvram/Bootline | awk '{print$8}' | cut -d'=' -f2"));
		strncpy(this_fw, chrCmd(output, 64, "cat /tmp/this_bank_iopver"), 64);
		strncpy(other_fw, chrCmd(output, 64, "cat /tmp/other_bank_iopver"), 64);

		blob_buf_init(&bb, 0);
		blobmsg_add_u32(&bb, "code", bank);
		blobmsg_add_string(&bb, "memory_bank", (bank)?"previous":"current");
		blobmsg_add_string(&bb, "current_bank_firmware", this_fw);
		blobmsg_add_string(&bb, "previous_bank_firmware", other_fw);
		ubus_send_reply(ctx, req, bb.head);
	}

	return 0;
}

struct ubus_method system_object_methods[] = {
	UBUS_METHOD_NOARG("fs", quest_router_filesystem),
	UBUS_METHOD_NOARG("info", quest_router_info),
	UBUS_METHOD_NOARG("logs", quest_router_logread),
	UBUS_METHOD("memory_bank", quest_memory_bank, bank_policy),
	UBUS_METHOD_NOARG("processes", quest_router_processes),
	UBUS_METHOD("password_set", quest_password_set, password_policy),
};

struct ubus_object_type system_object_type = UBUS_OBJECT_TYPE("system", system_object_methods);

struct ubus_object system_object = {
	.name = "router.system",
	.type = &system_object_type,
	.methods = system_object_methods,
	.n_methods = ARRAY_SIZE(system_object_methods),
};
