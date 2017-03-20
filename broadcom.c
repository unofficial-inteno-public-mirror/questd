/* -------------------------------------------------------------------------- */
#if IOPSYS_BROADCOM
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
#include <net/if.h>
#include <errno.h>

#include "tools.h"
#include "broadcom.h"
#include "bcmwifi_channels.h"

typedef enum {
	WL0,
	WL1
} WL;

static int iosocket = -1;
static int e_swap = 0;
static int wl_swap[sizeof(WL)] = { -1, -1 };

#define eswap64(val) ((e_swap)?BCMSWAP64(val):val)
#define eswap32(val) ((e_swap)?BCMSWAP32(val):val)
#define eswap16(val) ((e_swap)?BCMSWAP16(val):val)

#define AC_BUF_SIZE 50

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
	int val = 0;

	if(!strncmp(wl, "wl0", 3) && wl_swap[WL0] != -1) {
		e_swap = wl_swap[WL0];
		return 0;
	}

	if (!strncmp(wl, "wl1", 3) && wl_swap[WL1] != -1) {
		e_swap = wl_swap[WL1];
		return 0;
	}

	if ((ret = wl_ioctl(wl, WLC_GET_MAGIC, &val, sizeof(int))) < 0)
		return ret;

	/* Detect if IOCTL swapping is necessary */
	if (val == (int)BCMSWAP32(WLC_IOCTL_MAGIC))
		e_swap = 1;
	else
		e_swap = 0; /* restore it back in case it is called multiple times on different wl instance */

	if(!strncmp(wl, "wl0", 3))
		wl_swap[WL0] = e_swap;
	else if (!strncmp(wl, "wl1", 3))
		wl_swap[WL1] = e_swap;

	return 0;
}

/* This is not used
static int wl_iovar(const char *name, const char *cmd, const char *arg, int arglen, void *buf, int buflen)
{
	unsigned cmdlen = strlen(cmd) + 1;

	memcpy(buf, cmd, cmdlen);

	if (arg && arglen > 0)
		memcpy(buf + cmdlen, arg, arglen);

	return wl_ioctl(name, WLC_GET_VAR, buf, buflen);
}
*/

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
		memcpy(buf, ssid.ssid, 64);

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

int wl_get_wpa_auth(const char *ifname, char *wpa)
{
	unsigned int wpa_auth;
	int ret = 0;

	wl_endianness_check(ifname);

	if ((ret = wl_ioctl(ifname, WLC_GET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;

	wpa_auth = eswap32(wpa_auth);

	if (wpa_auth == WPA_AUTH_DISABLED)
		strcpy(wpa, "Disabled");
	else if ((wpa_auth & WPA_AUTH_PSK) && (wpa_auth & WPA2_AUTH_PSK))
		strcpy(wpa, "WPA/WPA2 PSK");
	else if (wpa_auth & WPA2_AUTH_PSK)
		strcpy(wpa, "WPA2 PSK");
	else if (wpa_auth & WPA_AUTH_PSK)
		strcpy(wpa, "WPA PSK");
	else if ((wpa_auth & WPA_AUTH_UNSPECIFIED) && (wpa_auth & WPA2_AUTH_UNSPECIFIED))
		strcpy(wpa, "WPA/WPA2 802.1x");
	else if (wpa_auth & WPA2_AUTH_UNSPECIFIED)
		strcpy(wpa, "WPA2 802.1x");
	else if (wpa_auth & WPA_AUTH_UNSPECIFIED)
		strcpy(wpa, "WPA 802.1x");
	else if (wpa_auth & WPA_AUTH_NONE)
		strcpy(wpa, "WPA-NONE");
	else if (wpa_auth & WPA2_AUTH_1X_SHA256)
		strcpy(wpa, "1X-SHA256");
	else if (wpa_auth & WPA2_AUTH_FT)
		strcpy(wpa, "FT");
	else if (wpa_auth & WPA2_AUTH_PSK_SHA256)
		strcpy(wpa, "PSK-SHA256");
	else
		strcpy(wpa, "Unknown");

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

int wl_get_bitrate(const char *ifname, unsigned long *buf)
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

int wl_get_maxrate(const char *ifname, int band, int bandwidth, unsigned long *buf)
{

	char output[32] = {0};
	bool fbf = false;

	chrCmd(output, 32, "wlctl -i %s revinfo | grep -c 'deviceid 0x43c5'", ifname);
	if (*output?atoi(output):0 == 1)
		fbf = true;

	if (band == 1) {
		if (bandwidth == 160)
			*buf = fbf?2166.5:2166.5;
		else if (bandwidth == 80)
			*buf = fbf?2166.5:1300;
		else if (bandwidth == 40)
			*buf = fbf?1000:600;
		else
			*buf = fbf?481:288.5;
	} else {
		if (bandwidth == 40)
			*buf = 300;
		else
			*buf = 144;
	}
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

int wl_get_isap(const char *ifname, int *buf)
{
	unsigned int isap;

	wl_endianness_check(ifname);

	if (wl_ioctl(ifname, WLC_GET_AP, &isap, sizeof(isap)) < 0)
		return -1;

	*buf = eswap32(isap);

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


void collect_security_info(char *encryption, char *cipher, wl_bss_info_t *bi)
{
	int ie_len = eswap32(bi->ie_length);
	bool is_wpa2 = false, have_wpa = false, have_wpa2 = false;
	uint8 *ie_start, *ie;
	uint16 tag, len, count, i;
	uint8 *wpaie = NULL, *ucast = NULL, *akm = NULL, *suite = NULL;
	uint8 ciphers_mask = 0;
	uint8 akm_mask = 0;
	int p, bit;
	uint8 oui_tag[3];

	ie_start = (uint8 *)((uint8 *)bi + eswap16(bi->ie_offset));

	for (ie = ie_start, len = ie[1];
			ie < ie_start + ie_len; ie += len + 2) {
		tag = *ie & 0x00FF;
		len = *(ie + 1);

		if (tag == 0x30 && !have_wpa2) {
			/* RSN */
			/* tag == DOT11_MNG_RSN_ID */
			is_wpa2 = true;
			have_wpa2 = true;
			memcpy(oui_tag, "\x00\x0F\xAC", 3); /* WPA2_OUI */
		} else if (tag == 0xDD && /* tag == DOT11_MNG_WPA_ID */
			!have_wpa &&
			(uint8)ie[2] == 0 && (uint8)ie[3] == 0x50
			&& (uint8)ie[4] == 0xF2 && (uint8)ie[5] == 0x01) {
			/* WPA */
			/*ie[2,3,4] == WPA_OUI && ie[5] == 0x01 */
			is_wpa2 = false;
			have_wpa = true;
			memcpy(oui_tag, "\x00\x50\xF2", 3); /* WPA_OUI */
		} else {
			continue;
		}

		/* parse wpa (ie) */
		wpaie = ie + sizeof(int16) + (is_wpa2?0:sizeof(char *));

		/* ignore the multicast suites */

		/* retrieve the unicast suites */
		ucast = wpaie + sizeof(int16) + sizeof(char *);
		count = ucast[0] | (ucast[1]<<8); /* always swap */
		for (i = 0; i < count; i++) {
			suite = ucast + sizeof(uint16) + i * sizeof(uint32);
			if (memcmp(suite, oui_tag, 3) != 0)
				continue;
			/* suite[0,1,2] == WPA_OUI */
			/* (uint8)suite[3] is one of the following:
			* WPA_CIPHER_NONE		0 None
			* WPA_CIPHER_WEP_40	1 WEP (40-bit)
			* WPA_CIPHER_TKIP		2 TKIP: default for WPA
			* WPA_CIPHER_AES_OCB	3 AES (OCB)
			* WPA_CIPHER_AES_CCM	4 AES (CCM)
			* WPA_CIPHER_WEP_103	5 WEP (104-bit)
			* WPA_CIPHER_BIP 6 WEP (104-bit)
			* WPA_CIPHER_TPK 7 Group addressed traffic not allowed
			*/
			ciphers_mask |= (1 << (uint8)suite[3]);

		}

		/* retrieve authentication key management */
		akm = ucast + sizeof(uint16) + count * sizeof(uint32);
		count = akm[0] | (akm[1]<<8); /* always swap */
		for (i = 0; i < count; i++) {
			suite = akm + sizeof(uint16) + i * sizeof(uint32);
			if (memcmp(suite, oui_tag, 3) != 0)
				continue;
			/* suite[0,1,2] == WPA_OUI */
			/* (uint8)suite[3] is one of the following:
			* RSN_AKM_NONE		0 None (IBSS)
			* RSN_AKM_UNSPECIFIED	1 Over 802.1x
			* RSN_AKM_PSK		2 Pre-shared Key
			* RSN_AKM_FBT_1X 3 Fast Bss transition using 802.1X
			* RSN_AKM_FBT_PSK 4 Fast Bss transition using PSK
			* RSN_AKM_MFP_1X 5 SHA256 key derivation, using 802.1X
			* RSN_AKM_MFP_PSK 6 SHA256 key derivation, using PSK
			* RSN_AKM_TPK	7 TPK(TDLS Peer Key) handshake
			*/
			akm_mask |= (1 << (uint8)suite[3]);
		}
	}

	for (p = 0; p < 8; p++) {
		bit = (ciphers_mask & (1<<p)) >> p;
		if (!bit)
			continue;
		if (cipher[0])
			strcat(cipher, "/");
		switch (p) {
		case 0:
			strcat(cipher, "NONE");
			break;
		case 1:
			strcat(cipher, "WEP_40");
			break;
		case 2:
			strcat(cipher, "TKIP");
			break;
		case 3:
			strcat(cipher, "AES_OCB");
			break;
		case 4:
			strcat(cipher, "AES_CCM");
			break;
		case 5:
			strcat(cipher, "WEP_104");
			break;
		case 6:
			strcat(cipher, "BIP");
			break;
		case 7:
			strcat(cipher, "TPK");
			break;
		default:
			strcat(cipher, "UNKNOWN");
			break;
		}
	}

	sprintf(encryption, "%s%s%s%s",
		have_wpa ? "WPA" : "",
		have_wpa && have_wpa2 ? "/" : "",
		have_wpa2 ? "WPA2" : "",
		have_wpa && have_wpa2 ? " " : "");

	for (p = 0; p < 8; p++) {
		bit = (akm_mask & (1<<p)) >> p;
		if (!bit)
			continue;
		if (encryption[strlen(encryption) - 1] != ' ')
			strcat(encryption, "/");
		switch (p) {
		case 0:
			strcat(encryption, "NONE");
			break;
		case 1:
			strcat(encryption, "802.1x");
			break;
		case 2:
			strcat(encryption, "PSK");
			break;
		case 3:
			strcat(encryption, "FT-802.1x");
			break;
		case 4:
			strcat(encryption, "FT-PSK");
			break;
		case 5:
			strcat(encryption, "MFP-802.1x");
			break;
		case 6:
			strcat(encryption, "MFP-PSK");
			break;
		case 7:
			strcat(encryption, "TPK");
			break;
		default:
			strcat(encryption, "UNKNOWN");
			break;
		}
	}

}


void dump_bss_info_summary(wl_bss_info_t *bi, struct blob_buf *b, int noise)
{
	char buf[512];
	char encryption[512] = {0};
	char cipher[512] = {0};
	int rssi;
	void *t;

	t = blobmsg_open_table(b, "");

	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		bi->BSSID.octet[0], bi->BSSID.octet[1], bi->BSSID.octet[2],
		bi->BSSID.octet[3], bi->BSSID.octet[4], bi->BSSID.octet[5]);
	blobmsg_add_string(b, "bssid", buf);

	rssi = eswap16((int16)(bi->RSSI));
	blobmsg_add_u32(b, "rssi", rssi);

	blobmsg_add_u32(b, "noise", bi->phy_noise);

	blobmsg_add_u32(b, "snr", rssi - noise);

	sprintf(buf, "%sGHz", CHSPEC_IS2G(eswap16(bi->chanspec))?"2.4":"5");
	blobmsg_add_string(b, "frequency", buf);


	blobmsg_add_u32(b, "channel", (bi->ctl_ch)?bi->ctl_ch:CHSPEC_CHANNEL(eswap16(bi->chanspec)));

	if (eswap32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap) {
		if (bi->vht_cap)
			sprintf(buf, "802.11: n/ac");
		else
			sprintf(buf, "802.11: b/g/n");
	}
	else {
		sprintf(buf, "802.11: b/g");
	}
	blobmsg_add_string(b, "mode", buf);

	wl_format_ssid(buf, bi->SSID, bi->SSID_len);
	blobmsg_add_string(b, "ssid", buf);


	collect_security_info(encryption, cipher, bi);
	if (!strlen(encryption))
		sprintf(encryption, "%s",
			(eswap16(bi->capability) & 0x0010) ? "WEP" : "OPEN");
	else
		blobmsg_add_string(b, "cipher", cipher);

	blobmsg_add_string(b, "encryption", encryption);

	blobmsg_close_table(b, t);
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

	if(channel != NULL)
		*channel = (bi->ctl_ch)?bi->ctl_ch:CHSPEC_CHANNEL(eswap16(bi->chanspec));
	if(noise != NULL)
		*noise = (int16)(bi->phy_noise);
	if(bandwidth != NULL)
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
	*buf = 0;

	memset(&revinfo, 0, sizeof (wlc_rev_info_t));
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

/* This is not used
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
*/

/* This is not used
int wl_get_sta_info(const char *ifname, char *bssid, unsigned long *stainfo)
{
	wl_sta_info_t *sta;
	struct wl_ether_addr ea;
	char *param;
	char buf[WLC_IOCTL_MEDLEN];
	int buflen, err;

	strcpy(buf, "sta_info");

	// convert the ea string into an ea struct
	if (!wl_ether_atoe(bssid, &ea)) {
		printf(" ERROR: no valid ether addr provided\n");
		return -1;
	}

	buflen = strlen(buf) + 1;
	param = (char *)(buf + buflen);
	memcpy(param, (char*)&ea, ETHER_ADDR_LEN);

	if ((err = wl_ioctl(ifname, WLC_GET_VAR, buf, WLC_IOCTL_MEDLEN)) < 0)
		return err;

	// display the sta info
	sta = (wl_sta_info_t *)buf;

	// Report unrecognized version
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
*/

int wl_get_stas_info(const char *ifname, char *bssid, struct wl_sta_info *sta_info, int *htcaps)
{
	FILE *stainfo;
	char cmnd[64];
	char line[256];
	int assoced = 0;

	sprintf(cmnd, "wlctl -i %s sta_info %s 2>/dev/null", ifname, bssid);
	if ((stainfo = popen(cmnd, "r"))) {
		while(fgets(line, sizeof(line), stainfo) != NULL)
		{
			assoced = 1;
			remove_newline(line);
			//sscanf(line, "[VER %d] STA %s:\n", &(sta_info->ver));
			//sscanf(line, "\t aid:%d ", &(sta_info->aid));
			//sscanf(line, "\t rateset");
			sscanf(line, "\t idle %d seconds", &(sta_info->idle));
			sscanf(line, "\t in network %d seconds", &(sta_info->in));
			//sscanf(line, "\t state: AUTHENTICATED ASSOCIATED AUTHORIZED");
			sscanf(line, "\t flags 0x%x:", &(sta_info->flags));
			sscanf(line, "\t HT caps 0x%x:", htcaps);
			sscanf(line, "\t VHT caps 0x%hu:", &(sta_info->vht_flags));
			sscanf(line, "\t tx total pkts: %u", &(sta_info->tx_tot_pkts));
			sscanf(line, "\t tx total bytes: %llu\n", &(sta_info->tx_tot_bytes));
			sscanf(line, "\t tx ucast pkts: %u", &(sta_info->tx_pkts));
			sscanf(line, "\t tx ucast bytes: %llu", &(sta_info->tx_ucast_bytes));
			sscanf(line, "\t tx mcast/bcast pkts: %u", &(sta_info->tx_mcast_pkts));
			sscanf(line, "\t tx mcast/bcast bytes: %llu", &(sta_info->tx_mcast_bytes));
			sscanf(line, "\t tx failures: %u", &(sta_info->tx_failures));
			sscanf(line, "\t rx data pkts: %u", &(sta_info->rx_tot_pkts));
			sscanf(line, "\t rx data bytes: %llu", &(sta_info->rx_tot_bytes));
			sscanf(line, "\t rx ucast pkts: %u", &(sta_info->rx_ucast_pkts));
			sscanf(line, "\t rx ucast bytes: %llu", &(sta_info->rx_ucast_bytes));
			sscanf(line, "\t rx mcast/bcast pkts: %u", &(sta_info->rx_mcast_pkts));
			sscanf(line, "\t rx mcast/bcast bytes: %llu", &(sta_info->rx_mcast_bytes));
			sscanf(line, "\t rate of last tx pkt: %u kbps - %u kbps", &(sta_info->tx_rate), &(sta_info->tx_rate_fallback));
			sscanf(line, "\t rate of last rx pkt: %u kbps", &(sta_info->rx_rate));
			sscanf(line, "\t rx decrypt succeeds: %u", &(sta_info->rx_decrypt_succeeds));
			sscanf(line, "\t rx decrypt failures: %u", &(sta_info->rx_decrypt_failures));
			sscanf(line, "\t tx data pkts retried: %u", &(sta_info->tx_pkts_retried));
			sscanf(line, "\t per antenna rssi of last rx data frame: %hhd %hhd %hhd %hhd", &(sta_info->rx_lastpkt_rssi[0]),
					&(sta_info->rx_lastpkt_rssi[1]), &(sta_info->rx_lastpkt_rssi[2]), &(sta_info->rx_lastpkt_rssi[3]));
			sscanf(line, "\t per antenna average rssi of rx data frames: %hhd %hhd %hhd %hhd", &(sta_info->rssi[0]), &(sta_info->rssi[1]),
					&(sta_info->rssi[2]), &(sta_info->rssi[3]));
			sscanf(line, "\t per antenna noise floor: %hhd %hhd %hhd %hhd", &(sta_info->nf[0]), &(sta_info->nf[1]),
					&(sta_info->nf[2]), &(sta_info->nf[3]));
			sscanf(line, "\t tx total pkts sent: %u", &(sta_info->tx_pkts_total));
			sscanf(line, "\t tx pkts retries: %u", &(sta_info->tx_pkts_retries));
			sscanf(line, "\t tx pkts retry exhausted: %u", &(sta_info->tx_pkts_retry_exhausted));
			sscanf(line, "\t tx FW total pkts sent: %u", &(sta_info->tx_pkts_fw_total));
			sscanf(line, "\t tx FW pkts retries: %u", &(sta_info->tx_pkts_fw_retries));
			sscanf(line, "\t tx FW pkts retry exhausted: %u", &(sta_info->tx_pkts_fw_retry_exhausted));
			sscanf(line, "\t rx total pkts retried: %u", &(sta_info->rx_pkts_retried));

		}
		pclose(stainfo);
	}

	return assoced;
}


int wl_scan(const char *ifname)
{
	int rv = 0;
	struct wl_scan_params params;

	wl_endianness_check(ifname);

	memset(&params, 0, sizeof(params));
	params.bss_type = DOT11_BSSTYPE_ANY;
	memset(&params.bssid, 0xFF, ETHER_ADDR_LEN);
	params.scan_type = (-1);
	params.nprobes = eswap32(-1);
	params.active_time = eswap32(-1);
	params.passive_time = eswap32(-1);
	params.home_time = eswap32(-1);
	params.channel_num = eswap32(0);

	rv = wl_ioctl(ifname, WLC_SCAN, &params, sizeof(params));

	return rv;
}

int wl_get_scanresults(const char *ifname, char *data, int size)
{
	int rv = 0;
	wl_scan_results_t *list = (wl_scan_results_t *)data;

	wl_endianness_check(ifname);

	memset(data, 0, size);
	list->buflen = eswap32(size);
	wl_endianness_check(ifname);


	size = eswap32(size);
	rv = wl_ioctl(ifname, WLC_SCAN_RESULTS, data, size);

	return rv;
}

void parse_scanresults_list(const char *radio, char *buf, struct blob_buf *b)
{
	wl_scan_results_t *list = (wl_scan_results_t*)buf;
	int count = eswap32(list->count);
	int version = eswap32(list->version);
	int noise;
	wl_bss_info_t *bi;
	uint i;

	if (count == 0) {
		return;
	}
	else if (version != WL_BSS_INFO_VERSION &&
			version != LEGACY2_WL_BSS_INFO_VERSION &&
			version != LEGACY_WL_BSS_INFO_VERSION) {
		/*             printf("Sorry, your driver has bss_info_version %d "*/
		/*                     "but this program supports only version %d.\n",*/
		/*                     version, WL_BSS_INFO_VERSION);*/
		return;
	}

	wl_get_bssinfo(radio, NULL, NULL, &noise);

	bi = list->bss_info;
	for (i = 0; i < count; i++) {
		dump_bss_info_summary(bi, b, noise);
		bi = (wl_bss_info_t*)(((int8*)bi) + (eswap32(bi->length)));
	}
}

int wl_autochannel(const char *ifname)
{
	char buf[AC_BUF_SIZE] = {0};

	chrCmd(buf, AC_BUF_SIZE, "acs_cli -i %s autochannel", ifname);
	return strncmp(buf, "Request finished", 16);
}

/* -------------------------------------------------------------------------- */
#endif /* IOPSYS_BROADCOM */
/* -------------------------------------------------------------------------- */

