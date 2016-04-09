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

#include "broadcom.h"
#include "bcmwifi_channels.h"

static int iosocket = -1;

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

int wl_iovar(const char *name, const char *cmd, const char *arg, int arglen, void *buf, int buflen)
{
	int cmdlen = strlen(cmd) + 1;

	memcpy(buf, cmd, cmdlen);

	if (arg && arglen > 0)
		memcpy(buf + cmdlen, arg, arglen);

	return wl_ioctl(name, WLC_GET_VAR, buf, buflen);
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

int wl_get_noise2(const char *ifname, int *buf)
{
	unsigned int ap, noise;
	int ioctl_req_version = 0x2000;
	char tmp[WLC_IOCTL_MAXLEN];

	memset(tmp, 0, WLC_IOCTL_MAXLEN);
	memcpy(tmp, &ioctl_req_version, sizeof(ioctl_req_version));

	wl_ioctl(ifname, WLC_GET_BSS_INFO, tmp, WLC_IOCTL_MAXLEN);

	if ((wl_ioctl(ifname, WLC_GET_AP, &ap, sizeof(ap)) < 0) || ap)
	{
		if (wl_ioctl(ifname, WLC_GET_PHY_NOISE, &noise, sizeof(noise)) < 0)
			noise = 0;
	}
	else
	{
		noise = tmp[WL_BSS_NOISE_OFFSET];
	}

	*buf = noise;

	return 0;
}

int wl_get_bitrate(const char *ifname, int *buf)
{
	int ret = -1;
	int rate = 0;

	if( !(ret = wl_ioctl(ifname, WLC_GET_RATE, &rate, sizeof(rate))) && (rate > 0))
		*buf = ((rate / 2) * 1000) + ((rate & 1) ? 500 : 0);

	return ret;
}

int wl_get_isup(const char *ifname, int *buf)
{
	unsigned int isup;

	if (wl_ioctl(ifname, WLC_GET_UP, &isup, sizeof(isup)) < 0)
		isup = 0;

	*buf = isup;

	return 0;
}

int wl_get_band(const char *ifname, int *buf)
{
	unsigned int band;

	if (wl_ioctl(ifname, WLC_GET_BAND, &band, sizeof(band)) < 0)
		band = 0;

	*buf = band;

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
	unsigned int ap;
	int ioctl_req_version = 0x2000;
	char tmp[WLC_IOCTL_MAXLEN];

	memset(tmp, 0, WLC_IOCTL_MAXLEN);
	memcpy(tmp, &ioctl_req_version, sizeof(ioctl_req_version));

	wl_ioctl(ifname, WLC_GET_BSS_INFO, tmp, WLC_IOCTL_MAXLEN);

/*	if (!wl_ioctl(ifname, WLC_GET_AP, &ap, sizeof(ap)) && !ap)*/
/*	{*/
/*		*buf = tmp[WL_BSS_RSSI_OFFSET];*/
/*	}*/

	bi = (wl_bss_info_t*)(tmp + 4);

	*channel = (bi->ctl_ch)?bi->ctl_ch:CHSPEC_CHANNEL(bi->chanspec);
	*noise = (int16)(bi->phy_noise);
	*bandwidth = (CHSPEC_IS160(bi->chanspec) ?
		160:(CHSPEC_IS80(bi->chanspec) ?
		80 : (CHSPEC_IS40(bi->chanspec) ?
		40 : (CHSPEC_IS20(bi->chanspec) ? 20 : 10))));

	//dump_bss_info_summary(bi);

	return 0;
}
