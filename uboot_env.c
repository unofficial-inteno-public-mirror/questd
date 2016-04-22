/*
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: fredrik.asberg@inteno.se
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdio.h> /* popen(), pclose(), fgets(), snprintf() */
#include <string.h> /* strchr(), strncmp(), strdup() */
#include <errno.h> /* errno */

#include "uboot_env.h"

/* -------------------------------------------------------------------------- */
#if IOPSYS_MARVELL
/* -------------------------------------------------------------------------- */

int uboot_env_get(const char *name, char **value)
{
	char buf[1024], *pos, *end;
	FILE *fp;
	int len;
	int rc;
	
	if (name == 0 || value == 0) {
		errno = EINVAL;
		return -1;
	}
	
	*value = ""; rc = 0;
	
	len = snprintf(buf, sizeof(buf), "fw_printenv %s", name);
	
	if (len < 0 || len >= sizeof(buf)) {
		errno = ENOBUFS;
		return -1;
	}
	
	if ((fp = popen(buf, "r")) == 0) {
		return -1;
	}
	
	if (fgets(buf, sizeof(buf), fp) == 0) {
		return -1;
	}
	
	if ((pos = strchr(buf, '=')) != 0) {
		if (strncmp(name, buf, (pos - buf)) == 0) {
			if ((end = strrchr(pos, '\n')) != 0) {
				*end = 0;
			}
			*value = strdup(1 + pos); rc = 1;
		}
	}
	
	if (pclose(fp) == -1) {
		return -1;
	}
	
	return rc;
}

int uboot_env_set(const char *name, const char *value)
{
	char buf[1024];
	FILE *fp;
	int len;
	
	if (name == 0) {
		errno = EINVAL;
		return -1;
	}
	if (value == 0) {
		value = "";
	}
	
	len = snprintf(buf, sizeof(buf), "fw_setenv %s %s", name, value);
	
	if (len < 0 || len >= sizeof(buf)) {
		errno = ENOBUFS;
		return -1;
	}
	
	if ((fp = popen(buf, "r")) == 0) {
		return -1;
	}
	
	if (pclose(fp) == -1) {
		return -1;
	}
	
	return 0;
}

int uboot_env_del(const char *name)
{
	return uboot_env_set(name, 0);
}

/* -------------------------------------------------------------------------- */
#endif /* IOPSYS_MARVELL */
/* -------------------------------------------------------------------------- */
#if IOPSYS_LANTIQ
/* -------------------------------------------------------------------------- */

int uboot_env_get(const char *name, char **value)
{
	char buf[1024], *end;
	FILE *fp;
	int len;
	int rc;
	
	if (name == 0 || value == 0) {
		errno = EINVAL;
		return -1;
	}
	
	*value = ""; rc = 0;
	
	len = snprintf(buf, sizeof(buf), "uboot_env --get --name %s", name);
	
	if (len < 0 || len >= sizeof(buf)) {
		errno = ENOBUFS;
		return -1;
	}
	
	if ((fp = popen(buf, "r")) == 0) {
		return -1;
	}
	
	if (fgets(buf, sizeof(buf), fp) == 0) {
		return -1;
	}
	
	if ((end = strrchr(buf, '\n')) != 0) {
		*end = 0;
	}
	
	*value = strdup(buf); rc = 1;
	
	if (pclose(fp) == -1) {
		return -1;
	}
	
	return rc;
}

int uboot_env_set(const char *name, const char *value)
{
	char buf[1024];
	FILE *fp;
	int len;
	
	if (name == 0) {
		errno = EINVAL;
		return -1;
	}
	if (value == 0) {
		value = "";
	}
	
	len = snprintf(buf, sizeof(buf), "uboot_env --set --name %s --value %s", name, value);
	
	if (len < 0 || len >= sizeof(buf)) {
		errno = ENOBUFS;
		return -1;
	}
	
	if ((fp = popen(buf, "r")) == 0) {
		return -1;
	}
	
	if (pclose(fp) == -1) {
		return -1;
	}
	
	return 0;
}

int uboot_env_del(const char *name)
{
	/* NOTE: This does not delete the actually key. */
	return uboot_env_set(name, "\"\"");
}

/* -------------------------------------------------------------------------- */
#endif /* IOPSYS_LANTIQ */
/* -------------------------------------------------------------------------- */

