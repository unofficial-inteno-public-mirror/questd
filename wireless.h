#define MAX_RADIO	4
#define MAX_VIF		8

typedef struct {
	const char *vif;
	const char *device;
	const char *ssid;
	const char *network;
} Wireless;

typedef struct {
	bool exists;
	char macaddr[24];
	char wdev[8];
} Sta;

typedef struct {
	const char *name;
	const char *band;
	int frequency;
	const char *hwmodes[6];
	int channels[64];
	int deviceid;
	int bwcaps[4];
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
