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
#include "broadcom.h"
#include "bcmwifi_channels.h"

/* -------------------------------------------------------------------------- */
#if IOPSYS_BROADCOM
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
	return wl_ioctl(ifname, WLC_GET_CHANNEL, buf, sizeof(buf));
}

int wl_get_ssid(const char *ifname, char *buf)
{
	int ret = -1;
	wlc_ssid_t ssid;

	if (!(ret = wl_ioctl(ifname, WLC_GET_SSID, &ssid, sizeof(ssid))))
		memcpy(buf, ssid.ssid, ssid.ssid_len);

	return ret;
}

int wl_get_bssid(const char *ifname, char *buf)
{
	int ret = -1;
	char bssid[6];

	if (!(ret = wl_ioctl(ifname, WLC_GET_BSSID, bssid, 6)))
		sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
			(uint8_t)bssid[0], (uint8_t)bssid[1], (uint8_t)bssid[2],
			(uint8_t)bssid[3], (uint8_t)bssid[4], (uint8_t)bssid[5]
		);

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
	wl_scb_val_t scb_val;
	int ret;

	if (!wl_ether_atoe(sta, &(scb_val.ea))) {
		printf("ERROR: no valid ether addr provided\n");
		return -1;
	}

	wl_endianness_check(ifname);

	if ((ret = wl_ioctl(ifname, WLC_GET_RSSI, &scb_val, sizeof(scb_val))) < 0)
		*buf = 0;
	else
		*buf = eswap32(scb_val.val);

	return 0;
}

int wl_get_bitrate(const char *ifname, int *buf)
{
	int ret = -1;
	int rate = 0;

	wl_endianness_check(ifname);

	if( !(ret = wl_ioctl(ifname, WLC_GET_RATE, &rate, sizeof(rate))) && (rate > 0))
		*buf = eswap32(rate);
		//*buf = ((eswap32(rate) / 2) * 1000) + ((rate & 1) ? 500 : 0);
	else
		*buf = 0;

	return ret;
}

int wl_get_isup(const char *ifname, int *buf)
{
	unsigned int isup;

	wl_endianness_check(ifname);

	if (wl_ioctl(ifname, WLC_GET_UP, &isup, sizeof(isup)) < 0)
		isup = 0;

	*buf = eswap32(isup);

	return 0;
}

int wl_get_band(const char *ifname, int *buf)
{
	unsigned int band;

	wl_endianness_check(ifname);

	if (wl_ioctl(ifname, WLC_GET_BAND, &band, sizeof(band)) < 0)
		band = 0;

	*buf = eswap32(band);

	return 0;
}

int
wl_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len)
{
	int i, c;
	char *p = ssid_buf;

	if (ssid_len > 32)
		ssid_len = 32;

	for (i = 0; i < ssid_len; i++) {
		c = (int)ssid[i];
		if (c == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (isprint((uchar)c)) {
			*p++ = (char)c;
		} else {
			p += sprintf(p, "\\x%02X", c);
		}
	}
	*p = '\0';

	return p - ssid_buf;
}

void dump_bss_info_summary(wl_bss_info_t *bi)
{
	char ssidbuf[SSID_FMT_BUF_LEN];

	wl_format_ssid(ssidbuf, bi->SSID, bi->SSID_len);

	printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\t",
		bi->BSSID.octet[0], bi->BSSID.octet[1], bi->BSSID.octet[2],
		bi->BSSID.octet[3], bi->BSSID.octet[4], bi->BSSID.octet[5]
	);
	printf("RSSI: %d dBm\t", (int16)(bi->RSSI));

	printf("Band: %sGHz\t", CHSPEC_IS2G(bi->chanspec)?"2.4":"5");
	printf("Channel: %d\t", (bi->ctl_ch)?bi->ctl_ch:CHSPEC_CHANNEL(bi->chanspec));
	printf("Noise: %d dBm\t", (int16)(bi->phy_noise));

	if (bi->version != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap) {
		if (bi->vht_cap)
			printf("802.11: n/ac\t");
		else
			printf("802.11: b/g/n\t");
	}
	else {
		printf("802.11: b/g\t");
	}

	printf("SSID: %s", ssidbuf);

	printf("\n");

	printf("\tChanspec: %sGHz channel %d %dMHz (0x%x)\n",
		CHSPEC_IS2G(bi->chanspec)?"2.4":"5", CHSPEC_CHANNEL(bi->chanspec),
		(CHSPEC_IS160(bi->chanspec) ?
		160:(CHSPEC_IS80(bi->chanspec) ?
		80 : (CHSPEC_IS40(bi->chanspec) ?
		40 : (CHSPEC_IS20(bi->chanspec) ? 20 : 10)))),
		bi->chanspec);
}

int wl_get_bssinfo(const char *ifname, int *bandwidth, int *channel, int *noise)
{
	wl_bss_info_t *bi;
/*	unsigned int ap;*/
	int ioctl_req_version = 0x2000;
	char tmp[WLC_IOCTL_MAXLEN];

	wl_endianness_check(ifname);

	memset(tmp, 0, WLC_IOCTL_MAXLEN);
	memcpy(tmp, &ioctl_req_version, sizeof(ioctl_req_version));

	wl_ioctl(ifname, WLC_GET_BSS_INFO, tmp, WLC_IOCTL_MAXLEN);

/*	if (!wl_ioctl(ifname, WLC_GET_AP, &ap, sizeof(ap)) && !ap)*/
/*	{*/
/*		*buf = tmp[WL_BSS_RSSI_OFFSET];*/
/*	}*/

	bi = (wl_bss_info_t*)(tmp + 4);

	*channel = (bi->ctl_ch)?bi->ctl_ch:CHSPEC_CHANNEL(eswap16(bi->chanspec));
	*noise = (int16)(bi->phy_noise);
	*bandwidth = (CHSPEC_IS160(eswap16(bi->chanspec)) ?
		160:(CHSPEC_IS80(eswap16(bi->chanspec)) ?
		80 : (CHSPEC_IS40(eswap16(bi->chanspec)) ?
		40 : (CHSPEC_IS20(eswap16(bi->chanspec)) ? 20 : 10))));

	return 0;
}

int wl_get_chanlist(const char *ifname, int *buf)
{
	uint32 chan_buf[WL_NUMCHANNELS + 1];
	wl_uint32_list_t *list;
	int ret, chan_count;
	uint i;

	wl_endianness_check(ifname);

	list = (wl_uint32_list_t *)(void *)chan_buf;
	list->count = eswap32(WL_NUMCHANNELS);
	ret = wl_ioctl(ifname, WLC_GET_VALID_CHANNELS, chan_buf, sizeof(chan_buf));
	if (ret < 0)
		return ret;

	chan_count = eswap32(list->count);

	for (i = 0; i < chan_count; i++) {
		buf[i] = eswap32(list->element[i]);
	}

	if (i < WL_NUMCHANNELS)
		buf[i+1] = 0;

	return ret;
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

int wl_get_stas_info(const char *ifname, char *bssid, unsigned long *buf)
{
	FILE *stainfo;
	char cmnd[64];
	char line[128];
	unsigned long tmp;

	sprintf(cmnd, "wlctl -i %s sta_info %s 2>/dev/null", ifname, bssid);
	if ((stainfo = popen(cmnd, "r"))) {
		while(fgets(line, sizeof(line), stainfo) != NULL)
		{
			remove_newline(line);
			sscanf(line, "\t idle %lu seconds", &(buf[0]));
			sscanf(line, "\t in network %lu seconds", &(buf[1]));
			sscanf(line, "\t tx total bytes: %lu\n", &(buf[2]));
			sscanf(line, "\t rx data bytes: %lu", &(buf[3]));
			sscanf(line, "\t rate of last tx pkt: %lu kbps - %lu kbps", &tmp, &(buf[4]));
			if (buf[4] < 0) buf[4] = tmp;
			sscanf(line, "\t rate of last rx pkt: %lu kbps", &(buf[5]));
		}
		pclose(stainfo);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */
#endif /* IOPSYS_BROADCOM */
/* -------------------------------------------------------------------------- */

