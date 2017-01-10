#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <glob.h>
#include <ctype.h>
#include <dirent.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <errno.h>

#include "tools.h"
#include "mediatek.h"

/* -------------------------------------------------------------------------- */
#ifdef IOPSYS_MEDIATEK
/* -------------------------------------------------------------------------- */

#define confile(val) (!strncmp(val, "rai", 3)) ? "/etc/Wireless/iNIC/iNIC_ap.dat" : "/etc/Wireless/RT2860/RT2860.dat"

int wl_get_channel(const char *ifname, int *buf)
{
	char channel[4];

	strcpy(channel, chrCmd("iwinfo %s info 2>/dev/null| grep Channel | awk '{print$4}'", ifname));	

	*buf = atoi(channel);
}

int wl_get_ssid(const char *ifname, char *buf)
{
	strcpy(buf, chrCmd("iwinfo %s info 2>/dev/null| grep ESSID | awk '{print$NF}' | tr -d '\"'", ifname));

	return 0;
}

int wl_get_bssid(const char *ifname, char *buf)
{
	strcpy(buf, chrCmd("iwinfo %s info 2>/dev/null | grep 'Access Point' | awk '{print$NF}'", ifname));

	return 0;
}

int wl_get_wpa_auth(const char *ifname, char *wpa)
{
	int ret = 0;

	strcpy(wpa, chrCmd("grep -w AuthMode %s | head -1 | cut -d'=' -f2", confile(ifname)));

	return ret;
}

int wl_get_wsec(const char *ifname, int *buf)
{

	return 0;
}

int wl_get_noise(const char *ifname, int *buf)
{
	return 0;
}

int wl_get_rssi(const char *ifname, char *sta, int *buf)
{
	*buf = -42;

	return 0;
}

int wl_get_bitrate(const char *ifname, int *buf)
{
	char rate[8];

	sprintf(rate, chrCmd("iwinfo %s info 2>/dev/null | grep 'Bit Rate' | awk '{print$3}' | cut -d'.' -f1", ifname));

	*buf = atoi(rate)*2;

	return 0;
}

int wl_get_isup(const char *ifname, int *buf)
{
	unsigned int isup;

	isup = atoi(chrCmd("ifconfig %s | grep -c UP", ifname));

	*buf = isup;

	return 0;
}

int wl_get_band(const char *ifname, int *buf)
{
	unsigned int band;

	if(!strncmp(ifname, "rai", 3))
		band = 1;
	else
		band = 0;

	*buf = band;

	return 0;
}

int wl_get_bssinfo(const char *ifname, int *bandwidth, int *channel, int *noise)
{
	char ch[4];

	strcpy(ch, chrCmd("iwinfo %s info 2>/dev/null | grep Channel | awk '{print$4}'", ifname));	

	*channel = atoi(ch);

	*noise = -85;

	if(!strncmp(ifname, "rai", 3))
		*bandwidth = 80;
	else
		*bandwidth = 20;

	return 0;
}

int wl_get_chanlist(const char *ifname, int *buf)
{
	if(!strncmp(ifname, "rai", 3)) {
		buf[0] = 36;
		buf[1] = 40;
		buf[2] = 44;
		buf[3] = 48;
		buf[4] = 52;
		buf[5] = 56;
		buf[6] = 60;
		buf[7] = 64;
		buf[8] = 100;
		buf[9] = 104;
		buf[10] = 108;
		buf[11] = 112;
		buf[12] = 116;
		buf[13] = 132;
		buf[14] = 136;
		buf[15] = 140;
	} else {
		buf[0] = 1;
		buf[1] = 2;
		buf[2] = 3;
		buf[3] = 4;
		buf[4] = 5;
		buf[5] = 6;
		buf[6] = 7;
		buf[7] = 8;
		buf[8] = 9;
		buf[9] = 10;
		buf[10] = 11;
		buf[11] = 12;
		buf[12] = 13;
	}

	return 0;
}

int wl_get_deviceid(const char *ifname, int *buf)
{

	return 0;
}

struct wl_maclist * wl_read_assoclist(const char *ifname)
{
	int socket_id;
	char name[25];
	char data[255];
	struct iwreq wrq;

	sprintf(name, ifname);
	strcpy(data, "get_mac_table");
	strcpy(wrq.ifr_name, name);
	wrq.u.data.length = strlen(data);
	//wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	fcntl(socket_id, F_SETFD, fcntl(socket_id, F_GETFD) | FD_CLOEXEC);

	ioctl(socket_id, RTPRIV_IOCTL_GET_MAC_TABLE, &wrq);

	printf("DATA is %s\n", wrq.u.name);

	return NULL;
}

void wl_get_stas_info(const char *ifname, char *bssid, struct wl_sta_info *sta_info, int *htcaps)
{
	sta_info->in = 20;
	sta_info->tx_tot_bytes = 1234;
	sta_info->rx_tot_bytes = 5678;
	sta_info->tx_rate_fallback = 0;
	sta_info->tx_rate = 866;
	sta_info->rx_rate = 458;
}

/* -------------------------------------------------------------------------- */
#endif /* IOPSYS_MEDIATEK */
/* -------------------------------------------------------------------------- */

