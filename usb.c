/*
 * usb -- collects usb info for questd
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

#include <string.h>

#include "questd.h"
#include "tools.h"
#include "usb.h"

#include <dirent.h>

static struct blob_buf bb;

static USB usb[MAX_USB];

char*
get_usb_infos(char *usbno, char *info) {
	FILE *in;
	char file[64];
	static char result[32];

	memset(result, '\0', sizeof(result));
	sprintf(file, "/sys/bus/usb/devices/%s/%s", usbno, info);
	if ((in = fopen(file, "r"))) {
		fgets(result, sizeof(result), in);
		remove_newline(result);
		fclose(in);
	}
	return result;
}

char*
get_usb_device(char *mount) {
	FILE *mounts;
	char line[128];
	static char dev[16];
	char mnt[64];

	if ((mounts = fopen("/var/usbmounts", "r"))) {
		while(fgets(line, sizeof(line), mounts) != NULL)
		{
			remove_newline(line);
			if (sscanf(line, "/dev/%s /mnt/%s", dev, mnt) == 2) {
				if (!strcmp(mnt, mount) || strstr(mount, mnt)) {
					break;
				}
			}
			memset(dev, '\0', sizeof(dev));
		}
		fclose(mounts);
	}
	return dev;
}

long
get_usb_size(char *device) {
	FILE *in;
	char file[64];
	char result[32];
	long size = 0;

	memset(result, '\0', sizeof(result));
	sprintf(file, "/sys/class/block/%s/size", device);
	if ((in = fopen(file, "r"))) {
		fgets(result, sizeof(result), in);
		remove_newline(result);
		fclose(in);
		size = (long)(atoi(result) / 2048);
	}
	return size;
}

void
dump_usb_info(USB *usb, char *usbno)
{
	FILE *in;
	char file[64];
	char result[32];

	sprintf(file, "/sys/bus/usb/devices/%s/product", usbno);
	if ((in = fopen(file, "r"))) {
		fgets(result, sizeof(result), in);
		remove_newline(result);
		fclose(in);

		memset(usb->netdevice, '\0', sizeof(usb->netdevice));
		memset(usb->device, '\0', sizeof(usb->device));

		strcpy(usb->product, result);
		memset(result, '\0', sizeof(result));
		sprintf(usb->no, "%s", usbno);
		strncpy(result, &usbno[2], strlen(usbno)-2);
		sprintf(usb->name, "USB%s", result);
		strncpy(usb->manufacturer, get_usb_infos(usb->no, "manufacturer"), 64);
		strncpy(usb->serial, get_usb_infos(usb->no, "serial"), 64);
		strncpy(usb->speed, get_usb_infos(usb->no, "speed"), 64);
		strncpy(usb->maxchild, get_usb_infos(usb->no, "maxchild"), 64);
		strncpy(usb->idproduct, get_usb_infos(usb->no, "idProduct"), 64);
		strncpy(usb->idvendor, get_usb_infos(usb->no, "idVendor"), 64);
		sprintf(usb->mount, "%s%s", usb->manufacturer, usb->serial);
		remove_space(usb->mount);
		if(!strcmp(usb->mount, usb->serial)) {
			sprintf(usb->mount, "%s%s", usb->product, usb->serial);
			remove_space(usb->mount);
		}
		strncpy(usb->netdevice, chrCmd("ls /sys/devices/platform/ehci-platform.*/*/driver/%s*/*/net/", usbno), 32);
		strncpy(usb->desc, chrCmd("cat /lib/network/wwan/%s:%s 2>/dev/null | grep desc | awk -F'[:,]' '{print$2}' | cut -d'\"' -f2", usb->idvendor, usb->idproduct), 128);
		strncpy(usb->device, get_usb_device(usb->mount), 64);
		usb->size = get_usb_size(usb->device);
	}
}

static void
router_dump_usbs(struct blob_buf *b)
{
	DIR *dir;
	struct dirent *ent;
	void *t;
	int uno = 0;

	memset(usb, '\0', sizeof(usb));
	if ((dir = opendir ("/sys/bus/usb/devices")) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if(uno >= MAX_USB) break;
			if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
				continue;
			if(strchr(ent->d_name, ':') || strstr(ent->d_name, "usb"))
				continue;

			dump_usb_info(&usb[uno], ent->d_name);

			if(strlen(usb[uno].product) < 1)
				continue;

			t = blobmsg_open_table(b, usb[uno].name);
			blobmsg_add_string(b, "idproduct", usb[uno].idproduct);
			blobmsg_add_string(b, "idvendor", usb[uno].idvendor);
			blobmsg_add_string(b, "product", usb[uno].product);
			blobmsg_add_string(b, "speed", usb[uno].speed);
			if (usb[uno].maxchild && strcmp(usb[uno].maxchild, "0")) {
				blobmsg_add_u32(b, "maxchild", atoi(usb[uno].maxchild));
			}
			else {
				blobmsg_add_string(b, "manufacturer", usb[uno].manufacturer);
				blobmsg_add_string(b, "serial", usb[uno].serial);
				if(strlen(usb[uno].device) > 1) {
					blobmsg_add_string(b, "device", usb[uno].device);
					blobmsg_add_u64(b, "size", usb[uno].size);
					blobmsg_add_string(b, "mntdir", usb[uno].mount);
				}
			}
			if(strlen(usb[uno].netdevice) > 2) {
				blobmsg_add_string(b, "netdevice", usb[uno].netdevice);
				blobmsg_add_string(b, "description", usb[uno].desc);
			}
			blobmsg_close_table(b, t);
			uno++;
		}
		closedir(dir);
	} else {
		perror ("Could not open /sys/bus/usb/devices directory");
	}
}

static int
quest_router_usbs(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	blob_buf_init(&bb, 0);
	router_dump_usbs(&bb);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

struct ubus_method usb_object_methods[] = {
	UBUS_METHOD_NOARG("status", quest_router_usbs),
};

struct ubus_object_type usb_object_type = UBUS_OBJECT_TYPE("usb", usb_object_methods);
