/*
 * network -- provides router.wireless object of questd
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

#include <sys/stat.h>

#include <libubox/blobmsg.h>
#include <libubus.h>
#include <uci.h>
#include <errno.h>

#include "network.h"
#include "tools.h"
#include "wireless.h"

enum {
	VIF_NAME,
	__WL_MAX,
};

static const struct blobmsg_policy vif_policy[__WL_MAX] = {
	[VIF_NAME] = { .name = "vif", .type = BLOBMSG_TYPE_STRING },
};

enum {
	SCAN_RADIO,
	__SCAN_MAX,
};

static const struct blobmsg_policy wl_scan_policy[__WL_MAX] = {
	[SCAN_RADIO] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
};

static struct uci_context *uci_ctx;
static struct uci_package *uci_wireless;
static struct blob_buf bb;

static Wireless wireless[MAX_VIF];
static Sta stas[MAX_CLIENT];
static Radio radio[MAX_RADIO];

void
wireless_assoclist()
{
	struct wl_maclist *macs = NULL;
	int sno = 0;
	int i, j;

	memset(stas, '\0', sizeof(stas));

	for (i = 0; i < MAX_VIF && strlen(wireless[i].device) > 0; i++) {
		if ((macs = wl_read_assoclist(wireless[i].vif)) != NULL)
		{
			for (j = 0; j < MAX_CLIENT && j < macs->count && sno < MAX_CLIENT; j++)
			{
				stas[sno].exists = true;
				sprintf(stas[sno].macaddr, "%02X:%02X:%02X:%02X:%02X:%02X",
					macs->ea[j].octet[0], macs->ea[j].octet[1], macs->ea[j].octet[2],
					macs->ea[j].octet[3], macs->ea[j].octet[4], macs->ea[j].octet[5]
				);
				strncpy(stas[sno].wdev, wireless[i].vif, 8);
				sno++;
			}

			free(macs);
		}
	}
}

bool
wireless_sta(Client *clnt)
{
	bool there = false;
	int i = 0;
	while(i < MAX_CLIENT && stas[i].exists) {
		if (!strcasecmp(stas[i].macaddr, clnt->macaddr)) {
			there = true;
			strncpy(clnt->wdev, stas[i].wdev, sizeof(clnt->wdev));
			break;
		}
		i++;
	}
	return there;
}

bool
wireless_sta6(Client6 *clnt)
{
	bool there = false;
	int i = 0;

	while(i < MAX_CLIENT && stas[i].exists) {
		if (!strcasecmp(stas[i].macaddr, clnt->macaddr)) {
			there = true;
			strncpy(clnt->wdev, stas[i].wdev, sizeof(clnt->wdev));
			break;
		}
		i++;
	}
	return there;
}

void
load_wireless()
{
	struct uci_element *e;
	const char *device, *network, *ssid, *band;
	int rno = 0, wno = 0, vif0 = 0, vif1 = 0, vif = 0;

	memset(wireless, '\0', sizeof(wireless));
	memset(radio, '\0', sizeof(radio));

	if((uci_wireless = init_package(&uci_ctx, "wireless"))) {
		uci_foreach_element(&uci_wireless->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (!strcmp(s->type, "wifi-iface")) {
				device = uci_lookup_option_string(uci_ctx, s, "device");
				network = uci_lookup_option_string(uci_ctx, s, "network");
				ssid = uci_lookup_option_string(uci_ctx, s, "ssid");
				if (device && strlen(device) && wno < MAX_VIF) {
					strncpy(wireless[wno].device, device, MAX_DEVICE_LENGTH-1);
					strncpy(wireless[wno].network, (network)? network : "", MAX_NETWORK_LENGTH-1);
					strncpy(wireless[wno].ssid, (ssid)? ssid : "", MAX_SSID_LENGTH-1);
				#if IOPSYS_BROADCOM
					if (!strcmp(device, "wl0")) {
						vif = vif0;
						vif0++;
					} else {
						vif = vif1;
						vif1++;
					}
					if (vif > 0)
						snprintf(wireless[wno].vif, MAX_VIF_LENGTH, "%s.%d", device, vif);
					else
						strncpy(wireless[wno].vif, device, MAX_VIF_LENGTH-1);
				#elif IOPSYS_MEDIATEK
					char dev[MAX_DEVICE_LENGTH] = {0};
					if (!strncmp(device, "ra0", 3)) {
						vif = vif0;
						vif0++;
					} else {
						vif = vif1;
						vif1++;
					}
					if (vif > 0) {
						strncpy(dev, device, strlen(device) - 1);
						snprintf(wireless[wno].vif, MAX_VIF_LENGTH, "%s%d", dev, vif);
					} else
						strncpy(wireless[wno].vif, device, MAX_VIF_LENGTH-1);
				#endif
					wno++;
				}
			} else if (!strcmp(s->type, "wifi-device")) {
				if (rno >= MAX_RADIO)
					continue;
				bool bw160 = false;
				strncpy(radio[rno].name, s->e.name, MAX_DEVICE_LENGTH-1);
				band = uci_lookup_option_string(uci_ctx, s, "band");
				strncpy(radio[rno].band, (band) ? band : "b", 8);
				radio[rno].frequency = !strcmp(radio[rno].band, "a") ? 5 : 2;
				radio[rno].is_ac = false;
			#if IOPSYS_BROADCOM
				wl_get_deviceid(radio[rno].name, &(radio[rno].deviceid));
				char output[32];
				memset(output, 0, 32);
				chrCmd(output, 32, "db -q get hw.%x.is_ac", radio[rno].deviceid);
				if (radio[rno].deviceid && *output?atoi(output):0 == 1)
					radio[rno].is_ac = true;
				memset(output, 0, 32);
				chrCmd(output, 32, "wlctl -i %s chanspecs | grep -c '0xe872'", radio[rno].name);
				if (*output?atoi(output):0 == 1)
					bw160 = true;
/*			#elif IOPSYS_MEDIATEK*/
/*				if (!strncmp(radio[rno].name, "rai", 3)) {*/
/*					radio[rno].is_ac = true;*/
/*					bw160 = true;*/
/*				}*/
			#endif

				if(radio[rno].frequency == 2) {
					radio[rno].hwmodes[0] = "11b";
					radio[rno].hwmodes[1] = "11g";
					radio[rno].hwmodes[2] = "11bg";
					radio[rno].hwmodes[3] = "11n";
					radio[rno].bwcaps[0] = 20;
					radio[rno].bwcaps[1] = 40;
					radio[rno].bwcaps[2] = '\0';
				} else if (radio[rno].frequency == 5) {
					radio[rno].hwmodes[0] = "11a";
					radio[rno].hwmodes[1] = "11n";
					radio[rno].hwmodes[2] = '\0';
					radio[rno].hwmodes[3] = '\0';
					radio[rno].bwcaps[0] = 20;
					radio[rno].bwcaps[1] = 40;
					radio[rno].bwcaps[2] = 80;
					if(bw160) {
						radio[rno].bwcaps[3] = 160;
						radio[rno].bwcaps[4] = '\0';
					} else {
						radio[rno].bwcaps[3] = '\0';
					}
					if (radio[rno].is_ac)
						radio[rno].hwmodes[2] = "11ac";
				}

				wl_get_chanlist(radio[rno].name, radio[rno].channels);

				rno++;
			}
		}
		free_uci_context(&uci_ctx);
	}
}

static void
router_dump_stas(struct blob_buf *b, char *wname, bool vif)
{
	void *t, *r, *bs_data_t;
	char compare[8];
	char stanum[8];
	int num = 1;
	int i, j;

	struct wl_sta_info sta_info;
	int bandwidth, channel, noise, rssi, snr;
	int htcaps, has_bs_data;
	struct bs_data bs;

	Client clients[MAX_CLIENT];

	get_network_clients(clients);

	for (i = 0; i < MAX_CLIENT && clients[i].exists; i++) {
		if (!(clients[i].wireless))
			continue;

		if(wname) {
			memset(compare, '\0', sizeof(compare));
			if (vif)
				strcpy(compare, clients[i].wdev);
			else
				strncpy(compare, clients[i].wdev, 3);

			if (strcmp(compare, wname))
				continue;
		}

		wl_get_stas_info(clients[i].wdev, clients[i].macaddr, &sta_info, &htcaps);
		wl_get_bssinfo(clients[i].wdev, &bandwidth, &channel, &noise);
		wl_get_rssi(clients[i].wdev, clients[i].macaddr, &rssi);
		memset(&bs, 0, sizeof(struct bs_data));
		has_bs_data = wl_bs_data(clients[i].wdev, clients[i].macaddr, &bs, 1);
		snr = rssi - noise;
		sta_info.ht_capabilities = htcaps;

		sprintf(stanum, "sta-%d", num);
		t = blobmsg_open_table(&bb, stanum);
		blobmsg_add_string(&bb, "hostname", clients[i].hostname);
		blobmsg_add_string(&bb, "ipaddr", clients[i].ipaddr);
		blobmsg_add_string(&bb, "macaddr", clients[i].macaddr);
		blobmsg_add_string(&bb, "network", clients[i].network);
		blobmsg_add_u8(&bb, "dhcp", clients[i].dhcp);
		if(strstr(clients[i].device, "br-"))
			blobmsg_add_string(&bb, "bridge", clients[i].device);
		blobmsg_add_string(&bb, "wdev", clients[i].wdev);
		blobmsg_add_string(&bb, "frequency", (channel >= 36) ? "5GHz" : "2.4GHz");
		blobmsg_add_u32(&bb, "rssi", rssi);
		blobmsg_add_u32(&bb, "snr", snr);
		blobmsg_add_u32(&bb, "idle", sta_info.idle);
		blobmsg_add_u32(&bb, "in_network", sta_info.in);
		if (has_bs_data == 0){
			bs_data_t = blobmsg_open_table(&bb, "bs_data");
			blobmsg_add_string(&bb, "phy_mbps", bs.phy_mbps);
			blobmsg_add_string(&bb, "data_mbps", bs.data_mbps);
			blobmsg_add_string(&bb, "air_use", bs.air_use);
			blobmsg_add_string(&bb, "data_use", bs.data_use);
			blobmsg_add_string(&bb, "retries", bs.retries);
			blobmsg_close_table(&bb, bs_data_t);
		}

#if IOPSYS_BROADCOM
		void *f, *h, *s, *v;

		f = blobmsg_open_table(&bb, "flags");
		blobmsg_add_u8(&bb, "brcm", (sta_info.flags & WL_STA_BRCM) ? true : false);
		blobmsg_add_u8(&bb, "wme", (sta_info.flags & WL_STA_WME) ? true : false);
		blobmsg_add_u8(&bb, "ps", (sta_info.flags & WL_STA_PS) ? true : false);
		blobmsg_add_u8(&bb, "no_erp", (sta_info.flags & WL_STA_NONERP) ? true : false);
		blobmsg_add_u8(&bb, "apsd_be", (sta_info.flags & WL_STA_APSD_BE) ? true : false);
		blobmsg_add_u8(&bb, "apsd_bk", (sta_info.flags & WL_STA_APSD_BK) ? true : false);
		blobmsg_add_u8(&bb, "apsd_vi", (sta_info.flags & WL_STA_APSD_VI) ? true : false);
		blobmsg_add_u8(&bb, "apsd_vo", (sta_info.flags & WL_STA_APSD_VO) ? true : false);
		blobmsg_add_u8(&bb, "n_cap", (sta_info.flags & WL_STA_N_CAP) ? true : false);
		blobmsg_add_u8(&bb, "vht_cap", (sta_info.flags & WL_STA_VHT_CAP) ? true : false);
		blobmsg_add_u8(&bb, "ampdu", (sta_info.flags & WL_STA_AMPDU_CAP) ? true : false);
		blobmsg_add_u8(&bb, "amsdu", (sta_info.flags & WL_STA_AMSDU_CAP) ? true : false);
		blobmsg_add_u8(&bb, "mimo_ps", (sta_info.flags & WL_STA_MIMO_PS) ? true : false);
		blobmsg_add_u8(&bb, "mimo_ps_rts", (sta_info.flags & WL_STA_MIMO_RTS) ? true : false);
		blobmsg_add_u8(&bb, "rifs", (sta_info.flags & WL_STA_RIFS_CAP) ? true : false);
		blobmsg_add_u8(&bb, "dwds_cap", (sta_info.flags & WL_STA_DWDS_CAP) ? true : false);
		blobmsg_add_u8(&bb, "dwds_active", (sta_info.flags & WL_STA_DWDS) ? true : false);
		blobmsg_close_table(&bb, f);

		h = blobmsg_open_table(&bb, "htcaps");
		blobmsg_add_u8(&bb, "ldpc", (sta_info.ht_capabilities & WL_STA_CAP_LDPC_CODING) ? true : false);
		blobmsg_add_u8(&bb, "bw40", (sta_info.ht_capabilities & WL_STA_CAP_40MHZ) ? true : false);
		blobmsg_add_u8(&bb, "gf", (sta_info.ht_capabilities & WL_STA_CAP_GF) ? true : false);
		blobmsg_add_u8(&bb, "sgi20", (sta_info.ht_capabilities & WL_STA_CAP_SHORT_GI_20) ? true : false);
		blobmsg_add_u8(&bb, "sgi40", (sta_info.ht_capabilities & WL_STA_CAP_SHORT_GI_40) ? true : false);
		blobmsg_add_u8(&bb, "stbc_tx", (sta_info.ht_capabilities & WL_STA_CAP_TX_STBC) ? true : false);
		blobmsg_add_u8(&bb, "stbc_rx", (sta_info.ht_capabilities & WL_STA_CAP_RX_STBC_MASK) ? true : false);
		blobmsg_add_u8(&bb, "d_block_ack", (sta_info.ht_capabilities & WL_STA_CAP_DELAYED_BA) ? true : false);
		blobmsg_add_u8(&bb, "intl40", (sta_info.ht_capabilities & WL_STA_CAP_40MHZ_INTOLERANT) ? true : false);
		blobmsg_close_table(&bb, h);

		if (sta_info.flags & WL_STA_VHT_CAP) {
			v = blobmsg_open_table(&bb, "vhtcaps");
			blobmsg_add_u8(&bb, "ldpc", (sta_info.vht_flags & WL_STA_VHT_LDPCCAP) ? true : false);
			blobmsg_add_u8(&bb, "sgi80", (sta_info.vht_flags & WL_STA_SGI80) ? true : false);
			blobmsg_add_u8(&bb, "sgi160", (sta_info.vht_flags & WL_STA_SGI160) ? true : false);
			blobmsg_add_u8(&bb, "stbc_tx", (sta_info.vht_flags & WL_STA_VHT_TX_STBCCAP) ? true : false);
			blobmsg_add_u8(&bb, "stbc_rx", (sta_info.vht_flags & WL_STA_VHT_RX_STBCCAP) ? true : false);
			blobmsg_add_u8(&bb, "su_bfr", (sta_info.vht_flags & WL_STA_SU_BEAMFORMER) ? true : false);
			blobmsg_add_u8(&bb, "su_bfe", (sta_info.vht_flags & WL_STA_SU_BEAMFORMEE) ? true : false);
			blobmsg_add_u8(&bb, "mu_bfr", (sta_info.vht_flags & WL_STA_MU_BEAMFORMER) ? true : false);
			blobmsg_add_u8(&bb, "mu_bfe", (sta_info.vht_flags & WL_STA_MU_BEAMFORMEE) ? true : false);
			blobmsg_add_u8(&bb, "txopps", (sta_info.vht_flags & WL_STA_VHT_TXOP_PS) ? true : false);
			blobmsg_add_u8(&bb, "vht_htc", (sta_info.vht_flags & WL_STA_HTC_VHT_CAP) ? true : false);
			blobmsg_close_table(&bb, v);
		}

		if (sta_info.flags & WL_STA_SCBSTATS)
		{
			s = blobmsg_open_table(&bb, "scbstats");
			blobmsg_add_u32(&bb, "tx_total_pkts", sta_info.tx_tot_pkts);
			blobmsg_add_u64(&bb, "tx_total_bytes", sta_info.tx_tot_bytes);
			blobmsg_add_u32(&bb, "tx_ucast_pkts", sta_info.tx_pkts);
			blobmsg_add_u64(&bb, "tx_ucast_bytes", sta_info.tx_ucast_bytes);
			blobmsg_add_u32(&bb, "tx_mcast_bcast_pkts", sta_info.tx_mcast_pkts);
			blobmsg_add_u64(&bb, "tx_mcast_bcast_bytes", sta_info.tx_mcast_bytes);
			blobmsg_add_u32(&bb, "tx_failures", sta_info.tx_failures);
			blobmsg_add_u32(&bb, "rx_data_pkts", sta_info.rx_tot_pkts);
			blobmsg_add_u64(&bb, "rx_data_bytes", sta_info.rx_tot_bytes);
			blobmsg_add_u32(&bb, "rx_ucast_pkts", sta_info.rx_ucast_pkts);
			blobmsg_add_u64(&bb, "rx_ucast_bytes", sta_info.rx_ucast_bytes);
			blobmsg_add_u32(&bb, "rx_mcast_bcast_pkts", sta_info.rx_mcast_pkts);
			blobmsg_add_u64(&bb, "rx_mcast_bcast_bytes", sta_info.rx_mcast_bytes);
			blobmsg_add_u32(&bb, "rate_of_last_tx_pkt", (sta_info.tx_rate_fallback > sta_info.tx_rate) ? sta_info.tx_rate_fallback : sta_info.tx_rate);
			blobmsg_add_u32(&bb, "rate_of_last_rx_pkt", sta_info.rx_rate);
			blobmsg_add_u32(&bb, "rx_decrypt_succeeds", sta_info.rx_decrypt_succeeds);
			blobmsg_add_u32(&bb, "rx_decrypt_failures", sta_info.rx_decrypt_failures);
			blobmsg_add_u32(&bb, "tx_data_pkts_retried", sta_info.tx_pkts_retried);
			blobmsg_add_u32(&bb, "tx_total_pkts_sent", sta_info.tx_pkts_total);
			blobmsg_add_u32(&bb, "tx_pkts_retries", sta_info.tx_pkts_retries);
			blobmsg_add_u32(&bb, "tx_pkts_retry_exhausted", sta_info.tx_pkts_retry_exhausted);
			blobmsg_add_u32(&bb, "tx_fw_total_pkts_sent", sta_info.tx_pkts_fw_total);
			blobmsg_add_u32(&bb, "tx_fw_pkts_retries", sta_info.tx_pkts_fw_retries);
			blobmsg_add_u32(&bb, "tx_fw_pkts_retry_exhausted", sta_info.tx_pkts_fw_retry_exhausted);
			blobmsg_add_u32(&bb, "rx_total_pkts_retried", sta_info.rx_pkts_retried);
			blobmsg_close_table(&bb, s);

			r = blobmsg_open_array(&bb, "rssi_per_antenna");
			for (j = 0; sta_info.rssi[j] && j < WL_STA_ANT_MAX; j++)
				blobmsg_add_u32(&bb, "", sta_info.rssi[j]);
			blobmsg_close_array(&bb, r);
		}
#else
			r = blobmsg_open_array(&bb, "rssi_per_antenna");
			for (j = 0; sta_info.rssi[j]; j++)
				blobmsg_add_u32(&bb, "", sta_info.rssi[j]);
			blobmsg_close_array(&bb, r);
#endif
		blobmsg_close_table(&bb, t);
		num++;
	}
}


static int
quest_router_vif_status(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__WL_MAX];
	struct stat s;
	char syspath[32];
	char wldev[8];

	blobmsg_parse(vif_policy, __WL_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[VIF_NAME]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(wldev, '\0', sizeof(wldev));
	strcpy(wldev, blobmsg_data(tb[VIF_NAME]));

#if IOPSYS_BROADCOM
	if(strncmp(wldev, "wl", 2))
		return UBUS_STATUS_INVALID_ARGUMENT;
#endif

	snprintf(syspath, 32, "/sys/class/net/%s", wldev);
	if (stat(syspath, &s))
		return UBUS_STATUS_INVALID_ARGUMENT;

	int isup;
	wl_get_isup(wldev, &isup);

	int band;
	wl_get_band(wldev, &band);

	char bssid[24] = {0};
	wl_get_bssid(wldev, bssid);

	char ssid[64] = {0};
	wl_get_ssid(wldev, ssid);

	char wpa_auth[64] = {0};
	wl_get_wpa_auth(wldev, wpa_auth);

	int wsec;
	wl_get_wsec(wldev, &wsec);

	unsigned long rate;
	wl_get_bitrate(wldev, &rate);

	int bandwidth, channel, noise;
	wl_get_bssinfo(wldev, &bandwidth, &channel, &noise);

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "wldev", wldev);
	blobmsg_add_u32(&bb, "radio", isup);
	blobmsg_add_string(&bb, "ssid", ssid);
	blobmsg_add_string(&bb, "bssid", bssid);
	blobmsg_add_string(&bb, "encryption", (wsec == 1 || wsec == 65) ? "WEP" : wpa_auth);
	blobmsg_add_u32(&bb, "frequency", (band==1)?5:2);
	blobmsg_add_u32(&bb, "channel", channel);
	blobmsg_add_u32(&bb, "bandwidth", bandwidth);
	blobmsg_add_u32(&bb, "noise", noise);
	blobmsg_add_u64(&bb, "rate", (rate/2));

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_stas(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__WL_MAX];

	blobmsg_parse(vif_policy, __WL_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	if (tb[VIF_NAME])
		router_dump_stas(&bb, blobmsg_data(tb[VIF_NAME]), true);
	else
		router_dump_stas(&bb, NULL, false);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_wl_assoclist(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct wl_sta_info sta_info;
	void *t;
	int bandwidth, channel, noise, rssi, snr, htcaps;
	int i;

	blob_buf_init(&bb, 0);

	for (i = 0; i < MAX_CLIENT && stas[i].exists; i++) {
		if(!wl_get_stas_info(stas[i].wdev, stas[i].macaddr, &sta_info, &htcaps))
			continue;

		wl_get_bssinfo(stas[i].wdev, &bandwidth, &channel, &noise);
		wl_get_rssi(stas[i].wdev, stas[i].macaddr, &rssi);
		snr = rssi - noise;

		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "wdev", stas[i].wdev);
		blobmsg_add_string(&bb, "macaddr", stas[i].macaddr);
		blobmsg_add_string(&bb, "frequency", (channel >= 36) ? "5GHz" : "2.4GHz");
		blobmsg_add_u32(&bb, "rssi", rssi);
		blobmsg_add_u32(&bb, "snr", snr);
		blobmsg_add_u32(&bb, "idle", sta_info.idle);
		blobmsg_add_u32(&bb, "in_network", sta_info.in);
		blobmsg_add_u8(&bb, "wme", (sta_info.flags & WL_STA_WME) ? true : false);
		blobmsg_add_u8(&bb, "ps", (sta_info.flags & WL_STA_PS) ? true : false);
		blobmsg_add_u8(&bb, "n_cap", (sta_info.flags & WL_STA_N_CAP) ? true : false);
		blobmsg_add_u8(&bb, "vht_cap", (sta_info.flags & WL_STA_VHT_CAP) ? true : false);
		blobmsg_add_u64(&bb, "tx_bytes", sta_info.tx_tot_bytes);
		blobmsg_add_u64(&bb, "rx_bytes", sta_info.rx_tot_bytes);
		blobmsg_add_u32(&bb, "tx_rate", (sta_info.tx_rate_fallback > sta_info.tx_rate) ? sta_info.tx_rate_fallback : sta_info.tx_rate);
		blobmsg_add_u32(&bb, "rx_rate", sta_info.rx_rate);
		blobmsg_close_table(&bb, t);
	}

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_scan(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__SCAN_MAX];
	char device[MAX_DEVICE_LENGTH];
	int i;
	bool found = false;

	blobmsg_parse(wl_scan_policy, __SCAN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[SCAN_RADIO]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(device, '\0', sizeof(device));
	strncpy(device, blobmsg_data(tb[SCAN_RADIO]), sizeof(device)-1);

	for(i = 0; i < MAX_RADIO; i++){
		if(!*radio[i].name)
			break;
		if(strncmp(radio[i].name, device, MAX_DEVICE_LENGTH) == 0){
			found = true;
			break;
		}
	}

	if(!found)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if(wl_scan(device) == 0)
		return UBUS_STATUS_OK;
	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int
quest_router_scanresults(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	char data[16380] = {0}; // fit 140 lines of 117 bytes
	struct blob_attr *tb[__SCAN_MAX];
	char device[MAX_DEVICE_LENGTH];
	int i;
	bool found = false;
	void *a;

	blobmsg_parse(wl_scan_policy, __SCAN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[SCAN_RADIO]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(device, '\0', sizeof(device));
	strncpy(device, blobmsg_data(tb[SCAN_RADIO]), sizeof(device)-1);

	for(i = 0; i < MAX_RADIO; i++){
		if(!*radio[i].name)
			break;
		if(strncmp(radio[i].name, device, MAX_DEVICE_LENGTH) == 0){
			found = true;
			break;
		}
	}

	if(!found)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if(wl_get_scanresults(device, data, sizeof(data)) != 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "access_points");
	parse_scanresults_list(device, data, &bb);
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	return UBUS_STATUS_OK;
}

static int
quest_router_radios(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *t, *c;
	int i, j;
	int isup, band,  bw, channel, noise;
	unsigned long rate;
#if IOPSYS_BROADCOM
	char maxrate[20];
#endif
	char bitrate[20];
	char frequency[10];
	char bandwidth[10];

	blob_buf_init(&bb, 0);

	for (i = 0; i < MAX_RADIO; i++) {
		if (strlen(radio[i].name) == 0)
			break;

		wl_get_isup(radio[i].name, &isup);

		wl_get_band(radio[i].name, &band);
		sprintf(frequency, "%sGHz", (band==1)?"5":"2.4");

		wl_get_bitrate(radio[i].name, &rate);
		sprintf(bitrate, "%g Mbps", (double)rate / 2);

		wl_get_bssinfo(radio[i].name, &bw, &channel, &noise);
		sprintf(bandwidth, "%dMHz", bw);

		t = blobmsg_open_table(&bb, radio[i].name);
		blobmsg_add_u8(&bb, "isup", isup);
		blobmsg_add_string(&bb, "frequency", frequency);
		blobmsg_add_string(&bb, "bandwidth", bandwidth);
		blobmsg_add_u32(&bb, "channel", channel);
		blobmsg_add_u32(&bb, "noise", noise);
#if IOPSYS_BROADCOM
		wl_get_maxrate(radio[i].name, band, bw, &rate);
		sprintf(maxrate, "%lu Mbps", rate);
		blobmsg_add_string(&bb, "rate", maxrate);
#else
		blobmsg_add_string(&bb, "rate", bitrate);
#endif
		c = blobmsg_open_array(&bb, "hwmodes");
		for(j=0; radio[i].hwmodes[j]; j++) {
			blobmsg_add_string(&bb, "", radio[i].hwmodes[j]);
		}
		blobmsg_close_array(&bb, c);
		c = blobmsg_open_array(&bb, "bwcaps");
		for(j=0; radio[i].bwcaps[j]; j++) {
			blobmsg_add_u32(&bb, "", radio[i].bwcaps[j]);
		}
		blobmsg_close_array(&bb, c);
		c = blobmsg_open_array(&bb, "channels");
		for(j=0; radio[i].channels[j] != 0; j++) {
			blobmsg_add_u32(&bb, "", radio[i].channels[j]);
		}
		blobmsg_close_array(&bb, c);
		blobmsg_close_table(&bb, t);
	}

	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static int
quest_router_autochannel(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	char device[MAX_DEVICE_LENGTH];
	bool found = false;
	int i, ch;
	struct blob_attr *tb[__SCAN_MAX];
	int ret;

	blobmsg_parse(wl_scan_policy, __SCAN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[SCAN_RADIO]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(device, '\0', sizeof(device));
	strncpy(device, blobmsg_data(tb[SCAN_RADIO]), sizeof(device)-1);

	for(i = 0; i < MAX_RADIO; i++){
		if(!*radio[i].name)
			break;
		if(strncmp(radio[i].name, device, MAX_DEVICE_LENGTH) == 0){
			found = true;
			break;
		}
	}

	if(!found)
		return UBUS_STATUS_INVALID_ARGUMENT;

	ret = wl_autochannel(device);

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "code", ret);
	if (ret == 0){
		ret = wl_get_channel(device, &ch);
		if(ret == 0)
			blobmsg_add_u32(&bb, "new_channel", ch);
		blobmsg_add_string(&bb, "status", "success");
	} else
		blobmsg_add_string(&bb, "status", "error");
	ubus_send_reply(ctx, req, bb.head);
	return 	UBUS_STATUS_OK;
}

#if IOPSYS_BROADCOM
static int
quest_bs_data(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__WL_MAX];
	struct bs_data bs[MAX_CLIENT];
	int ret, i;
	bool found = false;
	char vif[MAX_VIF_LENGTH];
	void *a, *t;

	blobmsg_parse(vif_policy, __WL_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);
	if (!tb[VIF_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	strncpy(vif, blobmsg_get_string(tb[VIF_NAME]), MAX_VIF_LENGTH);
	for(i = 0; i < MAX_VIF; i++){
		if(!*wireless[i].vif)
			break;
		if(strncmp(wireless[i].vif, vif, MAX_VIF_LENGTH) == 0){
			found = true;
			break;
		}
	}

	if(!found)
		return UBUS_STATUS_INVALID_ARGUMENT;

	ret = wl_bs_data(vif, NULL, bs, MAX_CLIENT);
	if (ret < 0)
		return UBUS_STATUS_UNKNOWN_ERROR;
	a = blobmsg_open_array(&bb, "stations");
	for (i = 0; i < ret; i++)
	{
		t = blobmsg_open_table(&bb, NULL);
		blobmsg_add_string(&bb, "macaddr", bs[i].macaddr);
		blobmsg_add_string(&bb, "phy_mbps", bs[i].phy_mbps);
		blobmsg_add_string(&bb, "data_mbps", bs[i].data_mbps);
		blobmsg_add_string(&bb, "air_use", bs[i].air_use);
		blobmsg_add_string(&bb, "data_use", bs[i].data_use);
		blobmsg_add_string(&bb, "retries", bs[i].retries);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}
#endif

struct ubus_method wireless_object_methods[] = {
	UBUS_METHOD("status", quest_router_vif_status, vif_policy),
	UBUS_METHOD("stas", quest_router_stas, vif_policy),
	UBUS_METHOD_NOARG("assoclist", quest_router_wl_assoclist),
	UBUS_METHOD_NOARG("radios", quest_router_radios),
	UBUS_METHOD("autochannel", quest_router_autochannel, wl_scan_policy),
	UBUS_METHOD("scan", quest_router_scan, wl_scan_policy),
	UBUS_METHOD("scanresults", quest_router_scanresults, wl_scan_policy),
#if IOPSYS_BROADCOM
	UBUS_METHOD("bs_data", quest_bs_data, vif_policy),
#endif
};

struct ubus_object_type wireless_object_type =
	UBUS_OBJECT_TYPE("wireless", wireless_object_methods);

struct ubus_object wireless_object = {
	.name = "router.wireless",
	.type = &wireless_object_type,
	.methods = wireless_object_methods,
	.n_methods = ARRAY_SIZE(wireless_object_methods),
};
