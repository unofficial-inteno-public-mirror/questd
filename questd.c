/*
 * questd -- router info daemon for Inteno CPEs
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

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <libubus.h>

#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <shadow.h>
#include <unistd.h>

#include "questd.h"
#include "tools.h"
#include "network.h"

#define DEFAULT_SLEEP	5000000

static struct ubus_context *ctx = NULL;
static struct blob_buf bb;
static const char *ubus_path;

static Router router;
static Memory memory;
static Key keys;
static Spec spec;

/* POLICIES */
enum {
	BANK,
	__BANK_MAX
};

static const struct blobmsg_policy bank_policy[__BANK_MAX] = {
	[BANK]     = { .name = "bank",     .type = BLOBMSG_TYPE_INT32 },
};
/* END POLICIES */

pthread_t tid[1];
pthread_mutex_t lock;
static long sleep_time = DEFAULT_SLEEP;

void recalc_sleep_time(bool calc, int toms)
{
	long dec = toms * 1000;
	if (!calc)
		sleep_time = DEFAULT_SLEEP;
	else if(sleep_time >= dec)
		sleep_time -= dec;
}

static void 
system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static int
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

static int
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

static int
quest_memory_bank(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__BANK_MAX];
	int bank;
	char this_fw[64];
	char other_fw[64];

	blobmsg_parse(bank_policy, __BANK_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[BANK]) {
		bank = blobmsg_get_u32(tb[BANK]);
		if (bank == 0 || bank == 1)
			runCmd("brcm_fw_tool set -u %d", bank);
		else
			return UBUS_STATUS_INVALID_ARGUMENT;
	} else {

		bank = atoi(chrCmd("cat /proc/nvram/Bootline | awk '{print$8}' | cut -d'=' -f2"));
		strncpy(this_fw, chrCmd("cat /tmp/this_bank_iopver"), 64);
		strncpy(other_fw, chrCmd("cat /tmp/other_bank_iopver"), 64);

		blob_buf_init(&bb, 0);
		blobmsg_add_u32(&bb, "code", bank);
		blobmsg_add_string(&bb, "memory_bank", (bank)?"previous":"current");
		blobmsg_add_string(&bb, "current_bank_firmware", this_fw);
		blobmsg_add_string(&bb, "previous_bank_firmware", other_fw);
		ubus_send_reply(ctx, req, bb.head);
	}

	return 0;
}

static int
quest_reload(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	dump_hostname(&router);
	load_networks();
#if IOPSYS_BROADCOM
	load_wireless();
#endif
	return 0;
}

/* ROUTER OBJECT */
extern int
quest_router_networks(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

extern int
quest_router_clients(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

static struct ubus_method router_object_methods[] = {
	UBUS_METHOD_NOARG("info", quest_router_info),
	UBUS_METHOD_NOARG("filesystem", quest_router_filesystem),
	UBUS_METHOD("memory_bank", quest_memory_bank, bank_policy),

	/* To be moved to router.network object */
	/* still here for backwards compatibility */
	UBUS_METHOD_NOARG("networks", quest_router_networks),
	UBUS_METHOD_NOARG("clients", quest_router_clients),

	UBUS_METHOD_NOARG("reload", quest_reload),
};

static struct ubus_object_type router_object_type =
	UBUS_OBJECT_TYPE("router", router_object_methods);

static struct ubus_object router_object = {
	.name = "router",
	.type = &router_object_type,
	.methods = router_object_methods,
	.n_methods = ARRAY_SIZE(router_object_methods),
};

/* NETWORK OBJECT */
extern int
igmp_snooping_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

extern int
ip_conntrack_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg);

extern struct ubus_method network_object_methods[6];
extern struct ubus_object_type network_object_type;

static struct ubus_object network_object = {
	.name = "router.network",
	.type = &network_object_type,
	.methods = network_object_methods,
	.n_methods = ARRAY_SIZE(network_object_methods),
};

#if IOPSYS_BROADCOM
/* WIRELESS OBJECT */
extern struct ubus_method wireless_object_methods[4];
extern struct ubus_object_type wireless_object_type();

static struct ubus_object wireless_object = {
	.name = "router.wireless",
	.type = &wireless_object_type,
	.methods = wireless_object_methods,
	.n_methods = ARRAY_SIZE(wireless_object_methods),
};

/* WPS OBJECT */
extern struct ubus_object_type wps_object_type;
extern struct ubus_method wps_object_methods[9];

static struct ubus_object wps_object = {
	.name = "router.wps",
	.type = &wps_object_type,
	.methods = wps_object_methods,
	.n_methods = ARRAY_SIZE(wps_object_methods),
};

/* DSL OBJECT */
extern struct ubus_object_type dsl_object_type;
extern struct ubus_method dsl_object_methods[1];

static struct ubus_object dsl_object = {
	.name = "router.dsl",
	.type = &dsl_object_type,
	.methods = dsl_object_methods,
	.n_methods = ARRAY_SIZE(dsl_object_methods),
};

/* PORT OBJECT */
extern struct ubus_method port_object_methods[1];

extern struct ubus_object_type port_object_type;

static struct ubus_object port_object = {
	.name = "router.port",
	.type = &port_object_type,
	.methods = port_object_methods,
	.n_methods = ARRAY_SIZE(port_object_methods),
};
#endif

/* SYSTEM OBJECT */
extern struct ubus_object_type system_object_type;
extern struct ubus_method system_object_methods[3];

static struct ubus_object system_object = {
	.name = "router.system",
	.type = &system_object_type,
	.methods = system_object_methods,
	.n_methods = ARRAY_SIZE(system_object_methods),
};

/* DROPBEAR OBJECT */
extern struct ubus_object_type dropbear_object_type;
extern struct ubus_method dropbear_object_methods[3];

static struct ubus_object dropbear_object = {
	.name = "router.dropbear",
	.type = &dropbear_object_type,
	.methods = dropbear_object_methods,
	.n_methods = ARRAY_SIZE(dropbear_object_methods),
};

/* USB OBJECT */
extern struct ubus_object_type usb_object_type;
extern struct ubus_method usb_object_methods[1];

static struct ubus_object usb_object = {
	.name = "router.usb",
	.type = &usb_object_type,
	.methods = usb_object_methods,
	.n_methods = ARRAY_SIZE(usb_object_methods),
};

static void
quest_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	system_fd_set_cloexec(ctx->sock.fd);
}

static void
quest_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = quest_ubus_reconnect_timer,
	};
	int t = 2;

	if (ubus_reconnect(ctx, ubus_path) != 0) {
		printf("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	printf("reconnected to ubus, new id: %08x\n", ctx->local_id);
	quest_ubus_add_fd();
}

static void
quest_ubus_connection_lost(struct ubus_context *ctx)
{
	quest_ubus_reconnect_timer(NULL);
}

static void
quest_add_object(struct ubus_object *obj)
{
	int ret = ubus_add_object(ctx, obj);

	if (ret != 0)
		fprintf(stderr, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
}

static int
quest_ubus_init(const char *path)
{
	uloop_init();
	ubus_path = path;

	ctx = ubus_connect(path);
	if (!ctx)
		return -EIO;

	printf("connected as %08x\n", ctx->local_id);
	ctx->connection_lost = quest_ubus_connection_lost;
	quest_ubus_add_fd();

	quest_add_object(&router_object);
	quest_add_object(&system_object);
	quest_add_object(&dropbear_object);
	quest_add_object(&usb_object);
	quest_add_object(&network_object);
#if IOPSYS_BROADCOM
	quest_add_object(&dsl_object);
	quest_add_object(&port_object);
	quest_add_object(&wireless_object);
	quest_add_object(&wps_object);
#endif

	return 0;
}

void *dump_router_info(void *arg)
{
	int lpcnt = 0;

	jiffy_counts_t cur_jif = {0}, prev_jif = {0};
	
	init_db_hw_config();
	load_networks();
#if IOPSYS_BROADCOM
	load_wireless();
#endif
	dump_keys(&keys);
	dump_specs(&spec);
	dump_static_router_info(&router);
	dump_hostname(&router);
	while (true) {
		pthread_mutex_lock(&lock);
		dump_cpuinfo(&router, &prev_jif, &cur_jif);
		populate_clients();
		pthread_mutex_unlock(&lock);
		get_jif_val(&prev_jif);
		usleep(sleep_time);
		recalc_sleep_time(false, 0);
		get_jif_val(&cur_jif);
		lpcnt++;
		if (lpcnt == 720) {
			lpcnt = 0;
			clear_clients();
		}
	}

	return NULL;
}

int main(int argc, char **argv)
{
	const char *path = NULL;
	int pt;

	if(argc > 1 && argv[1] && strlen(argv[1]) > 0){
		path = argv[1]; 
	}

	if (quest_ubus_init(path) < 0) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return 1;
	}

	if (pthread_mutex_init(&lock, NULL) != 0)
	{
		fprintf(stderr, "Failed to initialize mutex\n");
		return 1;
	}
	
	if ((pt = pthread_create(&(tid[0]), NULL, &dump_router_info, NULL) != 0)) {
		fprintf(stderr, "Failed to create thread\n");
		return 1;
	}

	uloop_run();
	pthread_mutex_destroy(&lock);
	ubus_free(ctx);	

	return 0;
}

