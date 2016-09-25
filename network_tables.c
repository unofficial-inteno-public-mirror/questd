#include "questd.h"
#include "tools.h"

static struct blob_buf bb;

int
igmp_snooping_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *snptable;
	void *t, *a;
	char line[256];
	char bridge[32];
	char device[32];
	char srcdev[32];
	char tags[32];
	char group[16];
	char mode[32];
	char RxGroup[16];
	char source[16];
	char reporter[16];
	int lantci, wantci, timeout, Index, ExcludPt;

	if ((snptable = fopen("/proc/net/igmp_snooping", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "table");
		while(fgets(line, sizeof(line), snptable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line),"%s %s %s %s %x %x %s %s %s %s %s %d %x %d",
					bridge, device, srcdev, tags, &(lantci), &(wantci),
					group, mode, RxGroup, source, reporter,
					&(timeout), &(Index), &(ExcludPt)) == 14)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"bridge", bridge);
				blobmsg_add_string(&bb,"device", device);
				blobmsg_add_string(&bb,"srcdev", srcdev);
				blobmsg_add_string(&bb,"tags", tags);
				blobmsg_add_u32(&bb,"lantci", lantci);
				blobmsg_add_u32(&bb,"wantci", wantci);
				blobmsg_add_string(&bb,"group", group);
				blobmsg_add_string(&bb,"mode", mode);
				blobmsg_add_string(&bb,"rxgroup", RxGroup);
				blobmsg_add_string(&bb,"source", source);
				blobmsg_add_string(&bb,"reporter", reporter);
				blobmsg_add_u32(&bb,"timeout", timeout);
				blobmsg_add_u32(&bb,"index", Index);
				blobmsg_add_u32(&bb,"excludpt", ExcludPt);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(snptable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

int
ip_conntrack_table(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	FILE *ipcntable;
	void *t, *a;
	char line[512];
	char state [64];
	char local_ip[24];
	char remote_ip[24];
	char tmps[64];
	int local_port, remote_port, tmpi;

	if ((ipcntable = fopen("/proc/net/ip_conntrack", "r"))) {
		blob_buf_init(&bb, 0);
		a = blobmsg_open_array(&bb, "table");
		while(fgets(line, sizeof(line), ipcntable) != NULL)
		{
			remove_newline(line);
			if(sscanf(single_space(line),"tcp %d %d %s src=%s dst=%s sport=%d dport=%d src=%s dst=%s sport=%d dport=%d %s mark=%d use=%d",
					&tmpi, &tmpi, state, tmps, tmps, &tmpi, &tmpi, local_ip, remote_ip, &local_port, &remote_port, tmps, &tmpi, &tmpi) == 14)
			{
				t = blobmsg_open_table(&bb, NULL);
				blobmsg_add_string(&bb,"proto", "tcp");
				blobmsg_add_string(&bb,"state", state);
				blobmsg_add_string(&bb,"local_ip", local_ip);
				blobmsg_add_string(&bb,"remote_ip", remote_ip);
				blobmsg_add_u32(&bb,"local_port", local_port);
				blobmsg_add_u32(&bb,"remote_port", remote_port);
				blobmsg_close_table(&bb, t);
			}
		}
		fclose(ipcntable);
		blobmsg_close_array(&bb, a);
		ubus_send_reply(ctx, req, bb.head);
	} else
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

