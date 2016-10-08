typedef struct {
	char mount[64];
	char product[64];
	char no[8];
	char name[8];
	unsigned long size;
	char device[64];
	char manufacturer[64];
	char serial[64];
	char speed[64];
	char maxchild[64];
	char idproduct[64];
	char idvendor[64];
	char netdevice[32];
	char desc[128];
} USB;

void dump_usb_info(USB *usb, char *usbno);

