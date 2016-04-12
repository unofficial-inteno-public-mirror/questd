/*
 * Custom OID/ioctl definitions for
 * Broadcom 802.11abg Networking Device Driver
 *
 * Definitions subject to change without notice.
 *
 * Copyright 2006, Broadcom Corporation
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

/* Reverse the bytes in a 16-bit value */
#define BCMSWAP16(val) \
	((uint16)((((uint16)(val) & (uint16)0x00ffU) << 8) | \
		  (((uint16)(val) & (uint16)0xff00U) >> 8)))

/* Reverse the bytes in a 32-bit value */
#define BCMSWAP32(val) \
	((uint32)((((uint32)(val) & (uint32)0x000000ffU) << 24) | \
		  (((uint32)(val) & (uint32)0x0000ff00U) <<  8) | \
		  (((uint32)(val) & (uint32)0x00ff0000U) >>  8) | \
		  (((uint32)(val) & (uint32)0xff000000U) >> 24)))

/* Reverse the bytes in a 64-bit value */
#define BCMSWAP64(val) \
	((uint64)((((uint64)(val) & 0x00000000000000ffULL) << 56) | \
	          (((uint64)(val) & 0x000000000000ff00ULL) << 40) | \
	          (((uint64)(val) & 0x0000000000ff0000ULL) << 24) | \
	          (((uint64)(val) & 0x00000000ff000000ULL) <<  8) | \
	          (((uint64)(val) & 0x000000ff00000000ULL) >>  8) | \
	          (((uint64)(val) & 0x0000ff0000000000ULL) >> 24) | \
	          (((uint64)(val) & 0x00ff000000000000ULL) >> 40) | \
	          (((uint64)(val) & 0xff00000000000000ULL) >> 56)))


#define SSID_FMT_BUF_LEN (4*32+1)	/* Length for SSID format string */
#define	LEGACY_WL_BSS_INFO_VERSION	107
#define MCSSET_LEN	16	/* 16-bits per 8-bit set to give 128-bits bitmap of MCS Index */
#define WL_STA_ANT_MAX		4	/**< max possible rx antennas */
#define WL_STA_VER		4
#define WL_NUMCHANNELS		64
#define	ETHER_ADDR_LEN		6
#define WLC_IOCTL_MEDLEN	1536    /* "med" length ioctl buffer required */

#include "typedefs.h"
#include "bcmwifi_channels.h"

#ifndef _BROADCOM_H
#define _BROADCOM_H

#define WL_MCSSET_LEN				16
#define WL_MAX_STA_COUNT			32

#define WLC_GET_PASSIVE				48

#define WL_BSS_RSSI_OFFSET			82
#define WL_BSS_NOISE_OFFSET			84

#define WLC_IOCTL_MAGIC				0x14e46c77
#define	WLC_IOCTL_MAXLEN			8192

#define WLC_CNTRY_BUF_SZ        		4

/* common ioctl definitions */
#define WLC_GET_MAGIC				0
#define WLC_GET_VERSION				1
#define WLC_UP					2
#define WLC_DOWN				3
#define WLC_GET_LOOP				4
#define WLC_SET_LOOP				5
#define WLC_DUMP				6
#define WLC_GET_MSGLEVEL			7
#define WLC_SET_MSGLEVEL			8
#define WLC_GET_PROMISC				9
#define WLC_SET_PROMISC				10
/* #define WLC_DUMP_RSSI			11 */ /* no longer supported */
#define WLC_GET_RATE				12
/* #define WLC_SET_RATE				13 */ /* no longer supported */
#define WLC_GET_INSTANCE			14
/* #define WLC_GET_FRAG				15 */ /* no longer supported */
/* #define WLC_SET_FRAG				16 */ /* no longer supported */
/* #define WLC_GET_RTS				17 */ /* no longer supported */
/* #define WLC_SET_RTS				18 */ /* no longer supported */
#define WLC_GET_INFRA				19
#define WLC_SET_INFRA				20
#define WLC_GET_AUTH				21
#define WLC_SET_AUTH				22
#define WLC_GET_BSSID				23
#define WLC_SET_BSSID				24
#define WLC_GET_SSID				25
#define WLC_SET_SSID				26
#define WLC_RESTART				27
/* #define WLC_DUMP_SCB				28 */ /* no longer supported */
#define WLC_GET_CHANNEL				29
#define WLC_SET_CHANNEL				30
#define WLC_GET_SRL				31
#define WLC_SET_SRL				32
#define WLC_GET_LRL				33
#define WLC_SET_LRL				34
#define WLC_GET_PLCPHDR				35
#define WLC_SET_PLCPHDR				36
#define WLC_GET_RADIO				37
#define WLC_SET_RADIO				38
#define WLC_GET_PHYTYPE				39
#define WLC_DUMP_RATE				40
#define WLC_SET_RATE_PARAMS			41
#define WLC_GET_FIXRATE				42
#define WLC_SET_FIXRATE				43
/* #define WLC_GET_WEP				42 */ /* no longer supported */
/* #define WLC_SET_WEP				43 */ /* no longer supported */
#define WLC_GET_KEY				44
#define WLC_SET_KEY				45
#define WLC_GET_REGULATORY			46
#define WLC_SET_REGULATORY			47
#define WLC_GET_PASSIVE_SCAN			48
#define WLC_SET_PASSIVE_SCAN			49
#define WLC_SCAN				50
#define WLC_SCAN_RESULTS			51
#define WLC_DISASSOC				52
#define WLC_REASSOC				53
#define WLC_GET_ROAM_TRIGGER			54
#define WLC_SET_ROAM_TRIGGER			55
#define WLC_GET_ROAM_DELTA			56
#define WLC_SET_ROAM_DELTA			57
#define WLC_GET_ROAM_SCAN_PERIOD		58
#define WLC_SET_ROAM_SCAN_PERIOD		59
#define WLC_EVM					60	/* diag */
#define WLC_GET_TXANT				61
#define WLC_SET_TXANT				62
#define WLC_GET_ANTDIV				63
#define WLC_SET_ANTDIV				64
/* #define WLC_GET_TXPWR			65 */ /* no longer supported */
/* #define WLC_SET_TXPWR			66 */ /* no longer supported */
#define WLC_GET_CLOSED				67
#define WLC_SET_CLOSED				68
#define WLC_GET_MACLIST				69
#define WLC_SET_MACLIST				70
#define WLC_GET_RATESET				71
#define WLC_SET_RATESET				72
/* #define WLC_GET_LOCALE			73 */ /* no longer supported */
#define WLC_LONGTRAIN				74
#define WLC_GET_BCNPRD				75
#define WLC_SET_BCNPRD				76
#define WLC_GET_DTIMPRD				77
#define WLC_SET_DTIMPRD				78
#define WLC_GET_SROM				79
#define WLC_SET_SROM				80
#define WLC_GET_WEP_RESTRICT			81
#define WLC_SET_WEP_RESTRICT			82
#define WLC_GET_COUNTRY				83
#define WLC_SET_COUNTRY				84
#define WLC_GET_PM				85
#define WLC_SET_PM				86
#define WLC_GET_WAKE				87
#define WLC_SET_WAKE				88
/* #define WLC_GET_D11CNTS			89 */ /* -> "counters" iovar */
#define WLC_GET_FORCELINK			90	/* ndis only */
#define WLC_SET_FORCELINK			91	/* ndis only */
#define WLC_FREQ_ACCURACY			92	/* diag */
#define WLC_CARRIER_SUPPRESS			93	/* diag */
#define WLC_GET_PHYREG				94
#define WLC_SET_PHYREG				95
#define WLC_GET_RADIOREG			96
#define WLC_SET_RADIOREG			97
#define WLC_GET_REVINFO				98
#define WLC_GET_UCANTDIV			99
#define WLC_SET_UCANTDIV			100
#define WLC_R_REG				101
#define WLC_W_REG				102
/* #define WLC_DIAG_LOOPBACK			103	old tray diag */
/* #define WLC_RESET_D11CNTS			104 */ /* -> "reset_d11cnts" iovar */
#define WLC_GET_MACMODE				105
#define WLC_SET_MACMODE				106
#define WLC_GET_MONITOR				107
#define WLC_SET_MONITOR				108
#define WLC_GET_GMODE				109
#define WLC_SET_GMODE				110
#define WLC_GET_LEGACY_ERP			111
#define WLC_SET_LEGACY_ERP			112
#define WLC_GET_RX_ANT				113
#define WLC_GET_CURR_RATESET			114	/* current rateset */
#define WLC_GET_SCANSUPPRESS			115
#define WLC_SET_SCANSUPPRESS			116
#define WLC_GET_AP				117
#define WLC_SET_AP				118
#define WLC_GET_EAP_RESTRICT			119
#define WLC_SET_EAP_RESTRICT			120
#define WLC_SCB_AUTHORIZE			121
#define WLC_SCB_DEAUTHORIZE			122
#define WLC_GET_WDSLIST				123
#define WLC_SET_WDSLIST				124
#define WLC_GET_ATIM				125
#define WLC_SET_ATIM				126
#define WLC_GET_RSSI				127
#define WLC_GET_PHYANTDIV			128
#define WLC_SET_PHYANTDIV			129
#define WLC_AP_RX_ONLY				130
#define WLC_GET_TX_PATH_PWR			131
#define WLC_SET_TX_PATH_PWR			132
#define WLC_GET_WSEC				133
#define WLC_SET_WSEC				134
#define WLC_GET_PHY_NOISE			135
#define WLC_GET_BSS_INFO			136
#define WLC_GET_PKTCNTS				137
#define WLC_GET_LAZYWDS				138
#define WLC_SET_LAZYWDS				139
#define WLC_GET_BANDLIST			140
#define WLC_GET_BAND				141
#define WLC_SET_BAND				142
#define WLC_SCB_DEAUTHENTICATE			143
#define WLC_GET_SHORTSLOT			144
#define WLC_GET_SHORTSLOT_OVERRIDE		145
#define WLC_SET_SHORTSLOT_OVERRIDE		146
#define WLC_GET_SHORTSLOT_RESTRICT		147
#define WLC_SET_SHORTSLOT_RESTRICT		148
#define WLC_GET_GMODE_PROTECTION		149
#define WLC_GET_GMODE_PROTECTION_OVERRIDE	150
#define WLC_SET_GMODE_PROTECTION_OVERRIDE	151
#define WLC_UPGRADE				152
/* #define WLC_GET_MRATE			153 */ /* no longer supported */
/* #define WLC_SET_MRATE			154 */ /* no longer supported */
#define WLC_GET_IGNORE_BCNS			155
#define WLC_SET_IGNORE_BCNS			156
#define WLC_GET_SCB_TIMEOUT			157
#define WLC_SET_SCB_TIMEOUT			158
#define WLC_GET_ASSOCLIST			159
#define WLC_GET_CLK				160
#define WLC_SET_CLK				161
#define WLC_GET_UP				162
#define WLC_OUT					163
#define WLC_GET_WPA_AUTH			164
#define WLC_SET_WPA_AUTH			165
#define WLC_GET_UCFLAGS				166
#define WLC_SET_UCFLAGS				167
#define WLC_GET_PWRIDX				168
#define WLC_SET_PWRIDX				169
#define WLC_GET_TSSI				170
#define WLC_GET_SUP_RATESET_OVERRIDE		171
#define WLC_SET_SUP_RATESET_OVERRIDE		172
/* #define WLC_SET_FAST_TIMER			173 */ /* no longer supported */
/* #define WLC_GET_FAST_TIMER			174 */ /* no longer supported */
/* #define WLC_SET_SLOW_TIMER			175 */ /* no longer supported */
/* #define WLC_GET_SLOW_TIMER			176 */ /* no longer supported */
/* #define WLC_DUMP_PHYREGS			177 */ /* no longer supported */
#define WLC_GET_PROTECTION_CONTROL		178
#define WLC_SET_PROTECTION_CONTROL		179
#define WLC_GET_PHYLIST				180
#define WLC_ENCRYPT_STRENGTH			181	/* ndis only */
#define WLC_DECRYPT_STATUS			182	/* ndis only */
#define WLC_GET_KEY_SEQ				183
#define WLC_GET_SCAN_CHANNEL_TIME		184
#define WLC_SET_SCAN_CHANNEL_TIME		185
#define WLC_GET_SCAN_UNASSOC_TIME		186
#define WLC_SET_SCAN_UNASSOC_TIME		187
#define WLC_GET_SCAN_HOME_TIME			188
#define WLC_SET_SCAN_HOME_TIME			189
#define WLC_GET_SCAN_NPROBES			190
#define WLC_SET_SCAN_NPROBES			191
#define WLC_GET_PRB_RESP_TIMEOUT		192
#define WLC_SET_PRB_RESP_TIMEOUT		193
#define WLC_GET_ATTEN				194
#define WLC_SET_ATTEN				195
#define WLC_GET_SHMEM				196	/* diag */
#define WLC_SET_SHMEM				197	/* diag */
/* #define WLC_GET_GMODE_PROTECTION_CTS		198 */ /* no longer supported */
/* #define WLC_SET_GMODE_PROTECTION_CTS		199 */ /* no longer supported */
#define WLC_SET_WSEC_TEST			200
#define WLC_SCB_DEAUTHENTICATE_FOR_REASON	201
#define WLC_TKIP_COUNTERMEASURES		202
#define WLC_GET_PIOMODE				203
#define WLC_SET_PIOMODE				204
#define WLC_SET_ASSOC_PREFER			205
#define WLC_GET_ASSOC_PREFER			206
#define WLC_SET_ROAM_PREFER			207
#define WLC_GET_ROAM_PREFER			208
#define WLC_SET_LED				209
#define WLC_GET_LED				210
#define WLC_GET_INTERFERENCE_MODE		211
#define WLC_SET_INTERFERENCE_MODE		212
#define WLC_GET_CHANNEL_QA			213
#define WLC_START_CHANNEL_QA			214
#define WLC_GET_CHANNEL_SEL			215
#define WLC_START_CHANNEL_SEL			216
#define WLC_GET_VALID_CHANNELS			217
#define WLC_GET_FAKEFRAG			218
#define WLC_SET_FAKEFRAG			219
#define WLC_GET_PWROUT_PERCENTAGE		220
#define WLC_SET_PWROUT_PERCENTAGE		221
#define WLC_SET_BAD_FRAME_PREEMPT		222
#define WLC_GET_BAD_FRAME_PREEMPT		223
#define WLC_SET_LEAP_LIST			224
#define WLC_GET_LEAP_LIST			225
#define WLC_GET_CWMIN				226
#define WLC_SET_CWMIN				227
#define WLC_GET_CWMAX				228
#define WLC_SET_CWMAX				229
#define WLC_GET_WET				230
#define WLC_SET_WET				231
#define WLC_GET_PUB				232
/* #define WLC_SET_GLACIAL_TIMER		233 */ /* no longer supported */
/* #define WLC_GET_GLACIAL_TIMER		234 */ /* no longer supported */
#define WLC_GET_KEY_PRIMARY			235
#define WLC_SET_KEY_PRIMARY			236
/* #define WLC_DUMP_RADIOREGS			237 */ /* no longer supported */
#define WLC_GET_ACI_ARGS			238
#define WLC_SET_ACI_ARGS			239
#define WLC_UNSET_CALLBACK			240
#define WLC_SET_CALLBACK			241
#define WLC_GET_RADAR				242
#define WLC_SET_RADAR				243
#define WLC_SET_SPECT_MANAGMENT			244
#define WLC_GET_SPECT_MANAGMENT			245
#define WLC_WDS_GET_REMOTE_HWADDR		246	/* handled in wl_linux.c/wl_vx.c */
#define WLC_WDS_GET_WPA_SUP			247
#define WLC_SET_CS_SCAN_TIMER			248
#define WLC_GET_CS_SCAN_TIMER			249
#define WLC_MEASURE_REQUEST			250
#define WLC_INIT				251
#define WLC_SEND_QUIET				252
#define WLC_KEEPALIVE			253
#define WLC_SEND_PWR_CONSTRAINT			254
#define WLC_UPGRADE_STATUS			255
#define WLC_CURRENT_PWR				256
#define WLC_GET_SCAN_PASSIVE_TIME		257
#define WLC_SET_SCAN_PASSIVE_TIME		258
#define WLC_LEGACY_LINK_BEHAVIOR		259
#define WLC_GET_CHANNELS_IN_COUNTRY		260
#define WLC_GET_COUNTRY_LIST			261
#define WLC_GET_VAR				262	/* get value of named variable */
#define WLC_SET_VAR				263	/* set named variable to value */
#define WLC_NVRAM_GET				264	/* deprecated */
#define WLC_NVRAM_SET				265
#define WLC_NVRAM_DUMP				266
#define WLC_REBOOT				267
#define WLC_SET_WSEC_PMK			268
#define WLC_GET_AUTH_MODE			269
#define WLC_SET_AUTH_MODE			270
#define WLC_GET_WAKEENTRY			271
#define WLC_SET_WAKEENTRY			272
#define WLC_NDCONFIG_ITEM			273	/* currently handled in wl_oid.c */
#define WLC_NVOTPW				274
#define WLC_OTPW				275
#define WLC_IOV_BLOCK_GET			276
#define WLC_IOV_MODULES_GET			277
#define WLC_SOFT_RESET				278
#define WLC_GET_ALLOW_MODE			279
#define WLC_SET_ALLOW_MODE			280
#define WLC_GET_DESIRED_BSSID			281
#define WLC_SET_DESIRED_BSSID			282
#define	WLC_DISASSOC_MYAP			283
#define WLC_GET_NBANDS				284	/* for Dongle EXT_STA support */
#define WLC_GET_BANDSTATES			285	/* for Dongle EXT_STA support */
#define WLC_GET_WLC_BSS_INFO			286	/* for Dongle EXT_STA support */
#define WLC_GET_ASSOC_INFO			287	/* for Dongle EXT_STA support */
#define WLC_GET_OID_PHY				288	/* for Dongle EXT_STA support */
#define WLC_SET_OID_PHY				289	/* for Dongle EXT_STA support */
#define WLC_SET_ASSOC_TIME			290	/* for Dongle EXT_STA support */
#define WLC_GET_DESIRED_SSID			291	/* for Dongle EXT_STA support */
#define WLC_GET_CHANSPEC			292	/* for Dongle EXT_STA support */
#define WLC_GET_ASSOC_STATE			293	/* for Dongle EXT_STA support */
#define WLC_SET_PHY_STATE			294	/* for Dongle EXT_STA support */
#define WLC_GET_SCAN_PENDING			295	/* for Dongle EXT_STA support */
#define WLC_GET_SCANREQ_PENDING			296	/* for Dongle EXT_STA support */
#define WLC_GET_PREV_ROAM_REASON		297	/* for Dongle EXT_STA support */
#define WLC_SET_PREV_ROAM_REASON		298	/* for Dongle EXT_STA support */
#define WLC_GET_BANDSTATES_PI			299	/* for Dongle EXT_STA support */
#define WLC_GET_PHY_STATE			300	/* for Dongle EXT_STA support */
#define WLC_GET_BSS_WPA_RSN			301	/* for Dongle EXT_STA support */
#define WLC_GET_BSS_WPA2_RSN			302	/* for Dongle EXT_STA support */
#define WLC_GET_BSS_BCN_TS			303	/* for Dongle EXT_STA support */
#define WLC_GET_INT_DISASSOC			304	/* for Dongle EXT_STA support */
#define WLC_SET_NUM_PEERS			305     /* for Dongle EXT_STA support */
#define WLC_GET_NUM_BSS				306	/* for Dongle EXT_STA support */
#define WLC_NPHY_SAMPLE_COLLECT			307	/* Nphy sample collect mode */
#define WLC_UM_PRIV				308	/* for usermode driver private ioctl */
#define WLC_GET_CMD				309
/* #define WLC_LAST				310 */	/* Never used - can be reused */
#define WLC_SET_INTERFERENCE_OVERRIDE_MODE	311	/* set inter mode override */
#define WLC_GET_INTERFERENCE_OVERRIDE_MODE	312	/* get inter mode override */
#define WLC_GET_WAI_RESTRICT			313	/* for WAPI */
#define WLC_SET_WAI_RESTRICT			314	/* for WAPI */
#define WLC_SET_WAI_REKEY			315	/* for WAPI */
#define WLC_LAST

/* uint32 list */
typedef struct wl_uint32_list {
	/* in - # of elements, out - # of entries */
	uint32 count;
	/* variable length uint32 list */
	uint32 element[1];
} wl_uint32_list_t;

struct wl_ether_addr {
	uint8_t					octet[6];
};

struct wl_maclist {
	uint					count;
	struct wl_ether_addr 	ea[1];
};

typedef struct wl_sta_rssi {
	int						rssi;
	char					mac[6];
	uint16_t				foo;
} wl_sta_rssi_t;

#define WL_NUMRATES     255 /* max # of rates in a rateset */
typedef struct wl_rateset {
    uint32_t  				count;          /* # rates in this set */
    uint8_t   				rates[WL_NUMRATES]; /* rates in 500kbps units w/hi bit set if basic */
} wl_rateset_t;

typedef struct wl_bss_info {
	uint32		version;		/**< version field */
	uint32		length;			/**< byte length of data in this record,
						 * starting at version and including IEs
						 */
	struct wl_ether_addr BSSID;
	uint16		beacon_period;		/**< units are Kusec */
	uint16		capability;		/**< Capability information */
	uint8		SSID_len;
	uint8		SSID[32];
	struct {
		uint	count;			/**< # rates in this set */
		uint8	rates[16];		/**< rates in 500kbps units w/hi bit set if basic */
	} rateset;				/**< supported rates */
	chanspec_t	chanspec;		/**< chanspec for bss */
	uint16		atim_window;		/**< units are Kusec */
	uint8		dtim_period;		/**< DTIM period */
	int16		RSSI;			/**< receive signal strength (in dBm) */
	int8		phy_noise;		/**< noise (in dBm) */

	uint8		n_cap;			/**< BSS is 802.11N Capable */
	uint32		nbss_cap;		/**< 802.11N+AC BSS Capabilities */
	uint8		ctl_ch;			/**< 802.11N BSS control channel number */
	uint8		padding1[3];		/**< explicit struct alignment padding */
	uint16		vht_rxmcsmap;	/**< VHT rx mcs map (802.11ac IE, VHT_CAP_MCS_MAP_*) */
	uint16		vht_txmcsmap;	/**< VHT tx mcs map (802.11ac IE, VHT_CAP_MCS_MAP_*) */
	uint8		flags;			/**< flags */
	uint8		vht_cap;		/**< BSS is vht capable */
	uint8		reserved[2];		/**< Reserved for expansion of BSS properties */
	uint8		basic_mcs[MCSSET_LEN];	/**< 802.11N BSS required MCS set */

	uint16		ie_offset;		/**< offset at which IEs start, from beginning */
	uint32		ie_length;		/**< byte length of Information Elements */
	int16		SNR;			/**< average SNR of during frame reception */
	uint16		vht_mcsmap;		/**< STA's Associated vhtmcsmap */
	uint16		vht_mcsmap_prop;	/**< STA's Associated prop vhtmcsmap */
	uint16		vht_txmcsmap_prop;	/**< prop VHT tx mcs prop */
	/* Add new fields here */
	/* variable length Information Elements */
} wl_bss_info_t;

/* Used to get specific STA parameters */
typedef struct wl_scb_val {
	uint32	val;
	struct wl_ether_addr ea;
} wl_scb_val_t;

/* Used to get specific link/ac parameters */
typedef struct wl_link_val {
	int ac;
	uint8 val;
	struct wl_ether_addr ea;
} wl_link_val_t;

/* Used by iovar versions of some ioctls, i.e. WLC_SCB_AUTHORIZE et al */
typedef struct wl_authops {
	uint32 code;
	wl_scb_val_t ioctl_args;
} wl_authops_t;

typedef struct wl_sta_info {
	uint16			ver;		/**< version of this struct */
	uint16			len;		/**< length in bytes of this structure */
	uint16			cap;		/**< sta's advertised capabilities */
	uint32			flags;		/**< flags defined below */
	uint32			idle;		/**< time since data pkt rx'd from sta */
	struct wl_ether_addr	ea;		/**< Station address */
	wl_rateset_t		rateset;	/**< rateset in use */
	uint32			in;		/**< seconds elapsed since associated */
	uint32			listen_interval_inms; /* Min Listen interval in ms for this STA */
	uint32			tx_pkts;	/**< # of user packets transmitted (unicast) */
	uint32			tx_failures;	/**< # of user packets failed */
	uint32			rx_ucast_pkts;	/**< # of unicast packets received */
	uint32			rx_mcast_pkts;	/**< # of multicast packets received */
	uint32			tx_rate;	/**< Rate used by last tx frame */
	uint32			rx_rate;	/**< Rate of last successful rx frame */
	uint32			rx_decrypt_succeeds;	/**< # of packet decrypted successfully */
	uint32			rx_decrypt_failures;	/**< # of packet decrypted unsuccessfully */
	uint32			tx_tot_pkts;	/**< # of user tx pkts (ucast + mcast) */
	uint32			rx_tot_pkts;	/**< # of data packets recvd (uni + mcast) */
	uint32			tx_mcast_pkts;	/**< # of mcast pkts txed */
	uint64			tx_tot_bytes;	/**< data bytes txed (ucast + mcast) */
	uint64			rx_tot_bytes;	/**< data bytes recvd (ucast + mcast) */
	uint64			tx_ucast_bytes;	/**< data bytes txed (ucast) */
	uint64			tx_mcast_bytes;	/**< # data bytes txed (mcast) */
	uint64			rx_ucast_bytes;	/**< data bytes recvd (ucast) */
	uint64			rx_mcast_bytes;	/**< data bytes recvd (mcast) */
	int8			rssi[WL_STA_ANT_MAX]; /* average rssi per antenna
										   * of data frames
										   */
	int8			nf[WL_STA_ANT_MAX];	/**< per antenna noise floor */
	uint16			aid;		/**< association ID */
	uint16			ht_capabilities;	/**< advertised ht caps */
	uint16			vht_flags;		/**< converted vht flags */
	uint32			tx_pkts_retried;	/**< # of frames where a retry was
							 * necessary
							 */
	uint32			tx_pkts_retry_exhausted; /* # of user frames where a retry
							  * was exhausted
							  */
	int8			rx_lastpkt_rssi[WL_STA_ANT_MAX]; /* Per antenna RSSI of last
								  * received data frame.
								  */
	/* TX WLAN retry/failure statistics:
	 * Separated for host requested frames and WLAN locally generated frames.
	 * Include unicast frame only where the retries/failures can be counted.
	 */
	uint32			tx_pkts_total;		/**< # user frames sent successfully */
	uint32			tx_pkts_retries;	/**< # user frames retries */
	uint32			tx_pkts_fw_total;	/**< # FW generated sent successfully */
	uint32			tx_pkts_fw_retries;	/**< # retries for FW generated frames */
	uint32			tx_pkts_fw_retry_exhausted;	/**< # FW generated where a retry
								 * was exhausted
								 */
	uint32			rx_pkts_retried;	/**< # rx with retry bit set */
	uint32			tx_rate_fallback;	/**< lowest fallback TX rate */
} wl_sta_info_t;

typedef struct wlc_ssid {
	uint32_t				ssid_len;
	unsigned char			ssid[32];
} wlc_ssid_t;

/* Linux network driver ioctl encoding */
typedef struct wl_ioctl {
	uint32_t				cmd;	/* common ioctl definition */
	void					*buf;	/* pointer to user buffer */
	uint32_t				len;	/* length of user buffer */
	uint8_t					set;	/* get or set request (optional) */
	uint32_t				used;	/* bytes read or written (optional) */
	uint32_t				needed;	/* bytes needed (optional) */
} wl_ioctl_t;

/*
 * Structure for passing hardware and software
 * revision info up from the driver.
 */
typedef struct wlc_rev_info {
	uint		vendorid;	/**< PCI vendor id */
	uint		deviceid;	/**< device id of chip */
	uint		radiorev;	/**< radio revision */
	uint		chiprev;	/**< chip revision */
	uint		corerev;	/**< core revision */
	uint		boardid;	/**< board identifier (usu. PCI sub-device id) */
	uint		boardvendor;	/**< board vendor (usu. PCI sub-vendor id) */
	uint		boardrev;	/**< board revision */
	uint		driverrev;	/**< driver version */
	uint		ucoderev;	/**< microcode version */
	uint		bus;		/**< bus type */
	uint		chipnum;	/**< chip number */
	uint		phytype;	/**< phy type */
	uint		phyrev;		/**< phy revision */
	uint		anarev;		/**< anacore rev */
	uint		chippkg;	/**< chip package info */
	uint		nvramrev;	/**< nvram revision number */
} wlc_rev_info_t;

typedef struct wl_country_list {
	uint32_t buflen;
	uint32_t band_set;
	uint32_t band;
	uint32_t count;
	char country_abbrev[1];
} wl_country_list_t;

int wl_get_channel(const char *ifname, int *buf);
int wl_get_ssid(const char *ifname, char *buf);
int wl_get_bssid(const char *ifname, char *buf);
int wl_get_noise(const char *ifname, int *buf);
int wl_get_rssi(const char *ifname, char *sta, int *buf);
int wl_get_bitrate(const char *ifname, int *buf);
int wl_get_isup(const char *ifname, int *buf);
int wl_get_band(const char *ifname, int *buf);
int wl_get_bssinfo(const char *ifname, int *bandwidth, int *channel, int *noise);
int wl_get_chanlist(const char *ifname, int *buf);
int wl_get_deviceid(const char *ifname, int *buf);
int wl_get_stainfo(const char *ifname, char *bssid, unsigned long *buf);
int wl_get_sta_info(const char *ifname, char *bssid, unsigned long *stainfo);
int wl_get_stas_info(const char *ifname, char *bssid, unsigned long *buf);

#endif
