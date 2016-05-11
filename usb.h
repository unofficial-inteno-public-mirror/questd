#ifndef Q_USB_H
#define Q_USB_H 1

typedef struct {  /* Used by: questd.c, dumper.h, usb.c */
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
} USB;

void dump_usb_info(USB *usb, char *usbno);

#endif /* Q_USB_H */

