#ifndef _IOPSYS_QUESTD_MEDIATEK_H
#define _IOPSYS_QUESTD_MEDIATEK_H

#include "typedefs.h"
#include <libubox/blobmsg.h>

#define WL_STA_ANT_MAX		4	/**< max possible rx antennas */
#define WL_STA_VER		4
#define WL_NUMCHANNELS		64
#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN		6
#endif

#define WL_MAX_STA_COUNT	32
/* Flags for sta_info_t indicating properties of STA */
#define WL_STA_BRCM		0x00000001	/* Running a Broadcom driver */
#define WL_STA_WME		0x00000002	/* WMM association */
#define WL_STA_NONERP		0x00000004	/* No ERP */
#define WL_STA_AUTHE		0x00000008	/* Authenticated */
#define WL_STA_ASSOC		0x00000010	/* Associated */
#define WL_STA_AUTHO		0x00000020	/* Authorized */
#define WL_STA_WDS		0x00000040	/* Wireless Distribution System */
#define WL_STA_WDS_LINKUP	0x00000080	/* WDS traffic/probes flowing properly */
#define WL_STA_PS		0x00000100	/* STA is in power save mode from AP's viewpoint */
#define WL_STA_APSD_BE		0x00000200	/* APSD delv/trigger for AC_BE is default enabled */
#define WL_STA_APSD_BK		0x00000400	/* APSD delv/trigger for AC_BK is default enabled */
#define WL_STA_APSD_VI		0x00000800	/* APSD delv/trigger for AC_VI is default enabled */
#define WL_STA_APSD_VO		0x00001000	/* APSD delv/trigger for AC_VO is default enabled */
#define WL_STA_N_CAP		0x00002000	/* STA 802.11n capable */
#define WL_STA_SCBSTATS		0x00004000	/* Per STA debug stats */
#define WL_STA_AMPDU_CAP	0x00008000	/* STA AMPDU capable */
#define WL_STA_AMSDU_CAP	0x00010000	/* STA AMSDU capable */
#define WL_STA_MIMO_PS		0x00020000	/* mimo ps mode is enabled */
#define WL_STA_MIMO_RTS		0x00040000	/* send rts in mimo ps mode */
#define WL_STA_RIFS_CAP		0x00080000	/* rifs enabled */
#define WL_STA_VHT_CAP		0x00100000	/* STA VHT(11ac) capable */
#define WL_STA_WPS		0x00200000	/* WPS state */
#define WL_STA_DWDS_CAP		0x01000000	/* DWDS CAP */
#define WL_STA_DWDS		0x02000000	/* DWDS active */

struct wl_ether_addr {
	uint8_t			octet[6];
};

struct wl_maclist {
	uint			count;
	struct wl_ether_addr	ea[1];
};

#define WL_NUMRATES     255 /* max # of rates in a rateset */
typedef struct wl_rateset {
    uint32_t  				count;          /* # rates in this set */
    uint8_t   				rates[WL_NUMRATES]; /* rates in 500kbps units w/hi bit set if basic */
} wl_rateset_t;

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

int wl_ether_atoe(const char *a, struct wl_ether_addr *n);
char* wl_ether_etoa(const struct wl_ether_addr *n);
int wl_get_channel(const char *ifname, int *buf);
int wl_scan(const char *ifname);
int wl_get_scanresult(const char *ifname, char *data, int size);
int wl_get_ssid(const char *ifname, char *buf);
int wl_get_bssid(const char *ifname, char *buf);
int wl_get_noise(const char *ifname, int *buf);
int wl_get_rssi(const char *ifname, char *sta, int *buf);
int wl_get_bitrate(const char *ifname, unsigned long *buf);
int wl_get_isup(const char *ifname, int *buf);
int wl_get_band(const char *ifname, int *buf);
int wl_get_bssinfo(const char *ifname, int *bandwidth, int *channel, int *noise);
int wl_get_chanlist(const char *ifname, int *buf);
int wl_get_deviceid(const char *ifname, int *buf);
int wl_get_stainfo(const char *ifname, char *bssid, unsigned long *buf);
int wl_get_sta_info(const char *ifname, char *bssid, unsigned long *stainfo);
int wl_get_stas_info(const char *ifname, char *bssid, struct wl_sta_info *sta_info, int *htcaps);
int wl_get_wpa_auth(const char *ifname, char *wpa);
int wl_get_wsec(const char *ifname, int *buf);
void parse_scanresult_list(char *buf, struct blob_buf *b);

struct wl_maclist * wl_read_assoclist(const char *ifname);







#define MAC_ADDR_LEN		6
#define MAX_NUMBER_OF_MAC	128


/* MIMO Tx parameter, ShortGI, MCS, STBC, etc.  these are fields in TXWI. Don't change this definition!!! */
typedef union _HTTRANSMIT_SETTING {
//#ifdef RT_BIG_ENDIAN
	struct {
		unsigned char MODE:3;	/* Use definition MODE_xxx. */
		unsigned char iTxBF:1;
		unsigned char eTxBF:1;
		unsigned char STBC:1;	/* only support in HT/VHT mode with MCS0~7 */
		unsigned char ShortGI:1;
		unsigned char BW:2;	/* channel bandwidth 20MHz/40/80 MHz */
		unsigned char ldpc:1;
		unsigned char MCS:6;	/* MCS */
	} field;
//#else
//	struct {
//		unsigned char MCS:6;
//		unsigned char ldpc:1;
//		unsigned char BW:2;
//		unsigned char ShortGI:1;
//		unsigned char STBC:1;
//		unsigned char eTxBF:1;
//		unsigned char iTxBF:1;
//		unsigned char MODE:3;
//	} field;
//#endif
	unsigned char word;
} HTTRANSMIT_SETTING, *PHTTRANSMIT_SETTING;

typedef struct _RT_802_11_MAC_ENTRY {
	unsigned char ApIdx;
	unsigned char Addr[MAC_ADDR_LEN];
	unsigned char Aid;
	unsigned char Psm;		/* 0:PWR_ACTIVE, 1:PWR_SAVE */
	unsigned char MimoPs;		/* 0:MMPS_STATIC, 1:MMPS_DYNAMIC, 3:MMPS_Enabled */
	char AvgRssi0;
	char AvgRssi1;
	char AvgRssi2;
	unsigned int ConnectedTime;
	HTTRANSMIT_SETTING TxRate;
	unsigned int LastRxRate;
/*
	sync with WEB UI's structure for ioctl usage.
*/
	short StreamSnr[3];				/* BF SNR from RXWI. Units=0.25 dB. 22 dB offset removed */
	short SoundingRespSnr[3];			/* SNR from Sounding Response. Units=0.25 dB. 22 dB offset removed */
/*	short TxPER;	*/					/* TX PER over the last second. Percent */
/*	short reserved;*/
} RT_802_11_MAC_ENTRY, *PRT_802_11_MAC_ENTRY;

typedef struct _RT_802_11_MAC_TABLE {
	unsigned long Num;
	RT_802_11_MAC_ENTRY Entry[MAX_NUMBER_OF_MAC];
} RT_802_11_MAC_TABLE, *PRT_802_11_MAC_TABLE;





/* Ralink defined OIDs */
#define RT_PRIV_IOCTL								(SIOCIWFIRSTPRIV + 0x01)
#define RTPRIV_IOCTL_SET							(SIOCIWFIRSTPRIV + 0x02)
#define RT_PRIV_IOCTL_EXT							(SIOCIWFIRSTPRIV + 0x0E) /* Sync. with RT61 (for wpa_supplicant) */
#ifdef DBG
#define RTPRIV_IOCTL_BBP                            (SIOCIWFIRSTPRIV + 0x03)
#define RTPRIV_IOCTL_MAC                            (SIOCIWFIRSTPRIV + 0x05)

#ifdef RTMP_RF_RW_SUPPORT
#define RTPRIV_IOCTL_RF                             (SIOCIWFIRSTPRIV + 0x13)
#endif /* RTMP_RF_RW_SUPPORT */

#endif /* DBG */
#define RTPRIV_IOCTL_E2P                            (SIOCIWFIRSTPRIV + 0x07)

#ifdef WCX_SUPPORT
#define MTPRIV_IOCTL_META_SET 						(SIOCIWFIRSTPRIV + 0x08)
#define MTPRIV_IOCTL_META_QUERY 					(SIOCIWFIRSTPRIV + 0x09)
#define MTPRIV_IOCTL_META_SET_EM					(SIOCIWFIRSTPRIV + 0x0B)
#define RTPRIV_IOCTL_STATISTICS                     (SIOCIWFIRSTPRIV + 0x15)
#else
#define RTPRIV_IOCTL_ATE							(SIOCIWFIRSTPRIV + 0x08)
#define RTPRIV_IOCTL_STATISTICS                     (SIOCIWFIRSTPRIV + 0x09)
#endif /* WCX_SUPPORT */

#define RTPRIV_IOCTL_ADD_PMKID_CACHE                (SIOCIWFIRSTPRIV + 0x0A)
#define RTPRIV_IOCTL_RADIUS_DATA                    (SIOCIWFIRSTPRIV + 0x0C)
#define RTPRIV_IOCTL_GSITESURVEY					(SIOCIWFIRSTPRIV + 0x0D)
#define RTPRIV_IOCTL_ADD_WPA_KEY                    (SIOCIWFIRSTPRIV + 0x0E)
#define RTPRIV_IOCTL_GET_MAC_TABLE					(SIOCIWFIRSTPRIV + 0x0F)
#define RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT	(SIOCIWFIRSTPRIV + 0x1F)	/* modified by Red@Ralink, 2009/09/30 */
#define RTPRIV_IOCTL_STATIC_WEP_COPY                (SIOCIWFIRSTPRIV + 0x10)

#define RTPRIV_IOCTL_SHOW							(SIOCIWFIRSTPRIV + 0x11)
#define RTPRIV_IOCTL_WSC_PROFILE                    (SIOCIWFIRSTPRIV + 0x12)
#define RTPRIV_IOCTL_QUERY_BATABLE                  (SIOCIWFIRSTPRIV + 0x16)
#ifdef INF_AR9
#define RTPRIV_IOCTL_GET_AR9_SHOW   (SIOCIWFIRSTPRIV + 0x17)
#endif/* INF_AR9 */
#define RTPRIV_IOCTL_SET_WSCOOB	(SIOCIWFIRSTPRIV + 0x19)
#define RTPRIV_IOCTL_WSC_CALLBACK	(SIOCIWFIRSTPRIV + 0x1A)
#define RTPRIV_IOCTL_RX_STATISTICS              (SIOCIWFIRSTPRIV + 0x1B)//Get CMD ID is odd; Set CMD ID is even 

#endif /*_IOPSYS_QUESTD_MEDIATEK_H*/
