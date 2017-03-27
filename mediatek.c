/* -------------------------------------------------------------------------- */
#ifdef IOPSYS_MEDIATEK
/* -------------------------------------------------------------------------- */

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

#include <linux/wireless.h>

#include "tools.h"
#include "mediatek.h"

#define confile(val) (!strncmp(val, "rai", 3)) ? "/etc/Wireless/iNIC/iNIC_ap.dat" : "/etc/Wireless/RT2860/RT2860.dat"

static int iosocket = -1;

static int wl_ioctl(const char *ifname, int cmd, char *arg, char *data, int len)
{
	int rv;
	char name[IFNAMSIZ];
	struct iwreq wrq;

	snprintf(name, IFNAMSIZ, ifname);
	if (arg)
		strcpy(data, arg);

	snprintf(wrq.ifr_ifrn.ifrn_name, IFNAMSIZ, name);
	wrq.u.data.pointer = data;
	wrq.u.data.length = len;
	wrq.u.data.flags = 0;

	if (iosocket == -1) {
		iosocket = socket(AF_INET, SOCK_DGRAM, 0);
		fcntl(iosocket, F_SETFD, fcntl(iosocket, F_GETFD) | FD_CLOEXEC);
	}

	rv = ioctl(iosocket, cmd, &wrq);

	switch (cmd) {
	case SIOCGIWFREQ:
		memcpy(data, &wrq.u.freq, sizeof(struct iw_freq));
		break;
	/*case SIOCGIWSENS:
		memcpy(data, &wrq.u.sens, sizeof(struct iw_param));
		break;*/
	case SIOCGIWAP:
		memcpy(data, &wrq.u.ap_addr, sizeof(struct sockaddr));
		break;
	case SIOCGIWRATE:
		memcpy(data, &wrq.u.bitrate, sizeof(struct iw_param));
		break;
	case SIOCGIFFLAGS:
		memcpy(data, &wrq.u, sizeof(short));
		break;
	}

	return rv;
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

int wl_get_channel(const char *ifname, int *channel)
{
	int rv;
	struct iw_freq freq;

	rv = wl_ioctl(ifname, SIOCGIWFREQ, NULL, (char *)&freq, 0);

	if(rv == -1)
		*channel = 0;
	else
		*channel = freq.m;

	return rv;
}

int wl_scan(const char *ifname)
{
	char data[255] = {0};
	strcpy(data, "SiteSurvey=1");

	return wl_ioctl(ifname, RTPRIV_IOCTL_SET, NULL, data, strlen(data)+1);
}

int wl_get_scanresults(const char *ifname, char *data, int size)
{
	return wl_ioctl(ifname, RTPRIV_IOCTL_GSITESURVEY, NULL, data, size);
}

int wl_get_ssid(const char *ifname, char *ssid)
{
	int rv;

	rv = wl_ioctl(ifname, SIOCGIWESSID, NULL, ssid, strlen(ssid));

	return rv;
}

int wl_get_bssid(const char *ifname, char *bssid)
{
	int rv;
	struct sockaddr ap_addr;

	rv = wl_ioctl(ifname, SIOCGIWAP, NULL, (char *)&ap_addr, 0);

	snprintf(bssid, 18, "%02X:%02X:%02X:%02X:%02X:%02X\n",
		(unsigned char) ap_addr.sa_data[0],
		(unsigned char) ap_addr.sa_data[1],
		(unsigned char) ap_addr.sa_data[2],
		(unsigned char) ap_addr.sa_data[3],
		(unsigned char) ap_addr.sa_data[4],
		(unsigned char) ap_addr.sa_data[5]);

	return rv;
}

int wl_get_wpa_auth(const char *ifname, char *wpa)
{
	int ret = 0;
	char output[64] = {0};

	chrCmd(output, 64, "grep -w AuthMode %s | head -1 | cut -d'=' -f2", confile(ifname));
	snprintf(wpa, 64, output);

	return ret;
}

int wl_get_wsec(const char *ifname, int *buf)
{
	*buf = 0;

	return 0;
}

int wl_get_noise(const char *ifname, int *noise)
{
	int rv = 0;

	/*
		SIOCGIWSENS is not implemented in the driver.
		Check drivers/net/wireless/mt_wifi/os/linux/ap_ioctl.c
		and  drivers/net/wireless/rlt_wifi/os/linux/ap_ioctl.c
		to see when it will be implemented.
	*/
	/*
	struct iw_param sens;
	rv = wl_ioctl(ifname, SIOCGIWSENS, NULL, (char *)&sens, 0);
	printf("wl_get_noise: %lu %d %d %d\n", sens.value, sens.fixed, sens.disabled, sens.flags);
	*noise = sens.value;
	*/

	/*
		SIOCGIWRANGE brings in some signal levels, but they are
		hardcoded at the moment, thus useless.
	*/
	/*
	struct iw_range range;
	wl_ioctl(ifname, SIOCGIWRANGE, NULL, (char *)&range, 0);
	printf ("iw_range: we_version %d %d max_qual %d %d %d \n",
		range.we_version_compiled, range.we_version_source,
		range.max_qual.qual, range.max_qual.level, range.max_qual.noise);
	*/

	*noise = -90;

	return rv;
}


int wl_get_rssi(const char *ifname, char *sta, int *buf)
{
	char data[20480] = {0};

	wl_ioctl(ifname, RTPRIV_IOCTL_GET_MAC_TABLE, NULL, data, strlen(data));

	RT_802_11_MAC_TABLE *mp;
	int i;

	mp = (RT_802_11_MAC_TABLE*) data;

	struct wl_ether_addr etheraddr;

	for (i=0; i < mp->Num; i++) {
		memcpy(etheraddr.octet, mp->Entry[i].Addr, sizeof(etheraddr.octet));
		if (!strcasecmp((char*) wl_ether_etoa(&(etheraddr)), sta)) {
			*buf =  (int)mp->Entry[i].AvgRssi0;
			break;
		}
	}

	return 0;
}

int wl_get_bitrate(const char *ifname, unsigned long *rate)
{
	int rv;
	struct iw_param bitrate;

	rv = wl_ioctl(ifname, SIOCGIWRATE, NULL, (char *)&bitrate, 0);

	*rate = bitrate.value / 1000000 * 2;

	return rv;
}

int wl_get_isup(const char *ifname, int *isup)
{
	int rv;
	short flags = 0;

	/*
	flags has the same purpose as ifr.ifr_flags
	inside the iwreq structture, flags is mapping exactly at the beginning of union iwreq_data u.
	(struct ifreq and struct iwreq have the exactly the same footprint)
	*/

	rv = wl_ioctl(ifname, SIOCGIFFLAGS, NULL, (char *)&flags, 0);

	/* printf("wl_get_is_up up %d bcast %d debug %d lo %d p2p %d run %d noarp %d promisc %d notr %d allmulti %d master %d  slave %d mcast %d portsel %d automedia %d dynamic %d lowup %d dormant %d echo %d\n",
			flags & IFF_UP,
			flags & IFF_BROADCAST,
			flags & IFF_DEBUG,
			flags & IFF_LOOPBACK,
			flags & IFF_POINTOPOINT,
			flags & IFF_RUNNING,
			flags & IFF_NOARP,
			flags & IFF_PROMISC,
			flags & IFF_NOTRAILERS,
			flags & IFF_ALLMULTI,
			flags & IFF_MASTER,
			flags & IFF_SLAVE,
			flags & IFF_MULTICAST,
			flags & IFF_PORTSEL,
			flags & IFF_AUTOMEDIA,
			flags & IFF_DYNAMIC,
			flags & IFF_LOWER_UP,
			flags & IFF_DORMANT,
			flags & IFF_ECHO);
	*/

	*isup = flags & IFF_UP;

	return rv;
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
	unsigned long rate;

	wl_get_channel(ifname, channel);
	wl_get_noise(ifname, noise);

	wl_get_bitrate(ifname, &rate);

	if((rate/2) > 300)
		*bandwidth = 80;
	else if((rate/2) > 144)
		*bandwidth = 40;
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

	if(!strncmp(ifname, "rai", 3)) {
		*buf = 0x7615;
	} else {
		*buf = 0x7603;
	}

	return 0;
}

struct wl_maclist * wl_read_assoclist(const char *ifname)
{
	char data[20480] = {0};

	wl_ioctl(ifname, RTPRIV_IOCTL_GET_MAC_TABLE, NULL, data, strlen(data));

	RT_802_11_MAC_TABLE *mp;
	int i;

	mp = (RT_802_11_MAC_TABLE*) data;

	struct wl_maclist *macs;
	int maclen = 4 + WL_MAX_STA_COUNT * 6;

	if(mp->Num < 1)
		return NULL;

	if ((macs = (struct wl_maclist *) malloc(maclen)) != NULL)
	{
		memset(macs, 0, maclen);
		macs->count = mp->Num;
		for (i=0; i < mp->Num; i++) {
			memcpy(macs->ea[i].octet, mp->Entry[i].Addr, sizeof(macs->ea[i].octet));
		}

		return macs;
	}

	return NULL;
}

int wl_get_stas_info(const char *ifname, char *bssid, struct wl_sta_info *sta_info, int *htcaps)
{
	char data[20480] = {0};

	wl_ioctl(ifname, RTPRIV_IOCTL_GET_MAC_TABLE, NULL, data, strlen(data));

	RT_802_11_MAC_TABLE *mp;
	int i;

	mp = (RT_802_11_MAC_TABLE*) data;

	struct wl_ether_addr etheraddr;

	for (i=0; i < mp->Num; i++) {
		memcpy(etheraddr.octet, mp->Entry[i].Addr, sizeof(etheraddr.octet));
		if (!strcasecmp((char*) wl_ether_etoa(&(etheraddr)), bssid)) {
			sta_info->in = (unsigned int)mp->Entry[i].ConnectedTime;
			sta_info->tx_tot_bytes = 0;
			sta_info->rx_tot_bytes = 0;
			sta_info->tx_rate_fallback = 0;
			//sta_info->tx_rate = (HTTRANSMIT_SETTING)mp->Entry[i].TxRate;
			sta_info->tx_rate = (unsigned int)mp->Entry[i].TxRate.word *1000;
			sta_info->rx_rate = (unsigned int)mp->Entry[i].LastRxRate * 1000;
			sta_info->rssi[0] =  (int)mp->Entry[i].AvgRssi0;
			sta_info->rssi[1] =  (int)mp->Entry[i].AvgRssi1;
			sta_info->rssi[2] =  (int)mp->Entry[i].AvgRssi2;

			return 1;
		}
	}

	return 0;
}

void parse_scanresults_list(const char *radio, char *buf, struct blob_buf *b)
{
	// EXAMPLE LINES:
	// 1   11  Inteno-D02A                      00:22:07:a9:d0:2a   WPA1PSKWPA2PSK/TKIPAES 2        11b/g/n ...
	// 11  Inteno-D02A                      00:22:07:a9:d0:2a   WPA1PSKWPA2PSK/TKIPAES 2        11b/g/n ...

	char ssid[34], bssid[21], security[24], mode[8], encryption[24], frequency[8];
	char line[200];
	char *line_p, *cipher_p, *newline;
	int str_len, band, channel, snr;
	void *t;

	wl_get_band(radio, &band);

	if(band == 1)
		strcpy(frequency, "5GHz");
	else
		strcpy(frequency, "2.4GHz");

	while(true){
		memset(line, 0, 200);
		newline = strchr(buf, '\n');
		if(newline == NULL)
			break;
		strncpy(line, buf, (newline - buf));
		line_p = line;
		str_len = strlen(line_p);
		if(str_len < 100){
			goto next;
		}
		if(str_len > 120){
			line_p += 4; // ignore index in 5GHz results
		}
		sscanf(line_p, "%4d", &channel);
		line_p += 4;
		memset(ssid, 0, 34);
		strncpy(ssid, line_p, 33);
		line_p += 33;
		trim(ssid);
		if(sscanf(line_p, "%20s%23s%9d%7s", bssid, security, &snr, mode) != 4)
			goto next;

		cipher_p = strchr(security, '/');
		if(cipher_p == NULL)
			goto next;

		memset(encryption, 0, 24);
		strncpy(encryption, security, (cipher_p - security));

		cipher_p ++; // remove leading /

		t = blobmsg_open_table(b, "");
		blobmsg_add_u32(b, "channel", channel);
		blobmsg_add_string(b, "ssid", ssid);
		blobmsg_add_string(b, "bssid", bssid);
		blobmsg_add_string(b, "encryption", encryption);
		blobmsg_add_string(b, "cipher", cipher_p);
		blobmsg_add_string(b, "frequency", frequency);
		blobmsg_add_u32(b, "snr", snr);
		blobmsg_add_string(b, "mode", mode);
		blobmsg_close_table(b, t);
next:
		buf = newline + 1;
	}
}
int wl_autochannel(const char *ifname)
{
	return chrCmd(NULL, 0, "iwpriv %s set AutoChannelSel=2", ifname);
}

/* -------------------------------------------------------------------------- */
#endif /* IOPSYS_MEDIATEK */
/* -------------------------------------------------------------------------- */

