#define MAX_RADIO	4
#define MAX_VIF		8
#define MAX_VIF_LENGTH 16
#define MAX_DEVICE_LENGTH 16
#define MAX_SSID_LENGTH 64
#define MAX_NETWORK_LENGTH 16

typedef struct {
	char vif[MAX_VIF_LENGTH];
	char device[MAX_DEVICE_LENGTH];
	char ssid[MAX_SSID_LENGTH];
	char network[MAX_NETWORK_LENGTH];
} Wireless;

typedef struct {
	bool exists;
	char macaddr[24];
	char wdev[8];
} Sta;

typedef struct {
	char name[MAX_DEVICE_LENGTH];
	char band[8];
	int frequency;
	//const char is ok. hwmodes are hard coded;
	const char *hwmodes[6];
	int channels[64];
	int deviceid;
	int bwcaps[6];
	bool is_ac;
} Radio;

typedef struct {
	bool brcm;
	bool wme;
	bool ps;
	bool nonerp;
	bool apsd_be;
	bool apsd_bk;
	bool apsd_vi;
	bool apsd_vo;
	bool n_cap;
	bool vht_cap;
	bool ampdu_cap;
	bool amsdu_cap;
	bool mimo_ps;
	bool mimo_rts;
	bool rifs_cap;
	bool dwds_cap;
	bool dwds_active;
	bool scbstats;
} Flags;

typedef struct {
	bool ldpc;
	bool bw40;
	bool gf;
	bool sgi20;
	bool sgi40;
	bool tx_stbc;
	bool rx_stbc;
	bool delayed_ba;
	bool intl40;
} HTCaps;

typedef struct {
	bool ldpc;
	bool sgi80;
	bool sgi160;
	bool tx_stbc;
	bool rx_stbc;
	bool su_bfr;
	bool su_bfe;
	bool mu_bfr;
	bool mu_bfe;
	bool txopps;
	bool htc_vht_cap;
} VHTCaps;

void wireless_assoclist(void);
void load_wireless(void);
bool wireless_sta(Client *clnt);
bool wireless_sta6(Client6 *clnt);
