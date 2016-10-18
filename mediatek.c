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
#include <net/if.h>
#include <errno.h>

#include "tools.h"
#include "mediatek.h"
#include "mtkwifi_channels.h"

/* -------------------------------------------------------------------------- */
#ifdef IOPSYS_MEDIATEK
/* -------------------------------------------------------------------------- */

typedef enum {
	WL0,
	WL0_1,
	WL1,
	WL1_1
} WL;

static int iosocket = -1;
static int e_swap = 0;
static int wl_swap[sizeof(WL)] = { -1, -1, -1, -1 };

#define eswap64(val) (e_swap)?BCMSWAP64(val):val
#define eswap32(val) (e_swap)?BCMSWAP32(val):val
#define eswap16(val) (e_swap)?BCMSWAP16(val):val

#define confile(val) (!strncmp(val, "rai", 3)) ? "/etc/Wireless/iNIC/iNIC_ap.dat" : "/etc/Wireless/RT2860/RT2860.dat"

static int wl_ioctl(const char *name, int cmd, void *buf, int len)
{
	struct ifreq ifr;
	wl_ioctl_t wioc;

	wioc.cmd = cmd;
	wioc.buf = buf;
	wioc.len = len;

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_data = (caddr_t) &wioc;

	if (iosocket == -1)
	{
		iosocket = socket(AF_INET, SOCK_DGRAM, 0);
		fcntl(iosocket, F_SETFD, fcntl(iosocket, F_GETFD) | FD_CLOEXEC);
	}

	return ioctl(iosocket, SIOCDEVPRIVATE, &ifr);
}

static int wl_endianness_check(const char *wl)
{
	int ret;
	int val;

	if(!strcmp(wl, "wl0") && wl_swap[WL0] != -1) {
		e_swap = wl_swap[WL0];
		return 0;
	}

	if (!strcmp(wl, "wl1") && wl_swap[WL1] != -1) {
		e_swap = wl_swap[WL1];
		return 0;
	}

	if(!strcmp(wl, "wl0.1") && wl_swap[WL0_1] != -1) {
		e_swap = wl_swap[WL0_1];
		return 0;
	}

	if(!strcmp(wl, "wl1.1") && wl_swap[WL1_1] != -1) {
		e_swap = wl_swap[WL1_1];
		return 0;
	}

	if ((ret = wl_ioctl(wl, WLC_GET_MAGIC, &val, sizeof(int))) < 0)
		return ret;

	/* Detect if IOCTL swapping is necessary */
	if (val == (int)BCMSWAP32(WLC_IOCTL_MAGIC))
		e_swap = 1;
	else
		e_swap = 0; /*retore it back in case it is called multiple times on different wl instance */

	if(!strcmp(wl, "wl0"))
		wl_swap[WL0] = e_swap;
	else if (!strcmp(wl, "wl1"))
		wl_swap[WL1] = e_swap;
	else if (!strcmp(wl, "wl0.1"))
		wl_swap[WL0_1] = e_swap;
	else if (!strcmp(wl, "wl1.1"))
		wl_swap[WL1_1] = e_swap;

	return 0;
}

static int wl_iovar(const char *name, const char *cmd, const char *arg, int arglen, void *buf, int buflen)
{
	unsigned cmdlen = strlen(cmd) + 1;

	memcpy(buf, cmd, cmdlen);

	if (arg && arglen > 0)
		memcpy(buf + cmdlen, arg, arglen);

	return wl_ioctl(name, WLC_GET_VAR, buf, buflen);
}

int
wl_ether_atoe(const char *a, struct wl_ether_addr *n)
{
	char *c = NULL;
	int i = 0;

	memset(n, 0, ETHER_ADDR_LEN);
	for (;;) {
		n->octet[i++] = (uint8)strtoul(a, &c, 16);
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
		a = c;
	}
	return (i == ETHER_ADDR_LEN);
}

char *
wl_ether_etoa(const struct wl_ether_addr *n)
{
	static char etoa_buf[ETHER_ADDR_LEN * 3];
	char *c = etoa_buf;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", n->octet[i] & 0xff);
	}
	return etoa_buf;
}

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
	unsigned int wsec;
	int ret = 0;

	wl_endianness_check(ifname);

	if ((ret = wl_ioctl(ifname, WLC_GET_WSEC, &wsec, sizeof(wsec))) < 0)
		return ret;

	wsec = eswap32(wsec);

	*buf = wsec;

	return ret;
}

int wl_get_noise(const char *ifname, int *buf)
{
	unsigned int noise;

	if (wl_ioctl(ifname, WLC_GET_PHY_NOISE, &noise, sizeof(noise)) < 0)
		noise = 0;

	*buf = noise;

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
	wlc_rev_info_t revinfo;

	wl_endianness_check(ifname);

	if (wl_ioctl(ifname, WLC_GET_REVINFO, &revinfo, sizeof(revinfo)))
		return -1;

	*buf = eswap32(revinfo.deviceid);

	return 0;
}

struct wl_maclist * wl_read_assoclist(const char *ifname)
{
	struct wl_maclist *macs;
	int maclen = 4 + WL_MAX_STA_COUNT * 6;

	if (strstr(ifname, "wds"))
		return NULL;

	wl_endianness_check(ifname);

	if ((macs = (struct wl_maclist *) malloc(maclen)) != NULL)
	{
		memset(macs, 0, maclen);
		macs->count = WL_MAX_STA_COUNT;

		if (!wl_ioctl(ifname, WLC_GET_ASSOCLIST, macs, maclen)) {
			macs->count = eswap32(macs->count);
			return macs;
		}

		free(macs);
	}

	return NULL;
}

int wl_get_stainfo(const char *ifname, char *bssid, unsigned long *buf)
{
	wl_sta_info_t sta;
	uint dummy[6];
	char mac[6];

	sscanf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
		&dummy[0], &dummy[1], &dummy[2],
		&dummy[3], &dummy[4], &dummy[5]
	);

	mac[0] = dummy[0];
	mac[1] = dummy[1];
	mac[2] = dummy[2];
	mac[3] = dummy[3];
	mac[4] = dummy[4];
	mac[5] = dummy[5];

	if (!wl_iovar(ifname, "sta_info", mac, 6, &sta, sizeof(sta)) && (sta.ver >= 2))
	{
		buf[0] = sta.idle;
		buf[1] = sta.in;
		buf[2] = sta.tx_tot_bytes;
		buf[3] = sta.rx_tot_bytes;
		buf[4] = sta.tx_rate;
		buf[5] = sta.rx_rate;
	}

	return 0;
}

int wl_get_sta_info(const char *ifname, char *bssid, unsigned long *stainfo)
{
	wl_sta_info_t *sta;
	struct wl_ether_addr ea;
	char *param;
	char buf[WLC_IOCTL_MEDLEN];
	int buflen, err;

	strcpy(buf, "sta_info");

	/* convert the ea string into an ea struct */
	if (!wl_ether_atoe(bssid, &ea)) {
		printf(" ERROR: no valid ether addr provided\n");
		return -1;
	}

	buflen = strlen(buf) + 1;
	param = (char *)(buf + buflen);
	memcpy(param, (char*)&ea, ETHER_ADDR_LEN);

	if ((err = wl_ioctl(ifname, WLC_GET_VAR, buf, WLC_IOCTL_MEDLEN)) < 0)
		return err;

	/* display the sta info */
	sta = (wl_sta_info_t *)buf;

	/* Report unrecognized version */
	if (sta->ver > WL_STA_VER) {
		printf(" ERROR: unknown driver station info version %d\n", sta->ver);
		return -1;
	}

	stainfo[0] = sta->idle;
	stainfo[1] = sta->in;
	stainfo[2] = sta->tx_tot_bytes;
	stainfo[3] = sta->rx_tot_bytes;
	stainfo[4] = sta->tx_rate;
	stainfo[5] = sta->rx_rate;

	return 0;
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

