#define INTERVAL	5000000

/* OBJECTS */
struct ubus_object net_object;
struct ubus_object network_object;
struct ubus_object directory_object;
#if IOPSYS_BROADCOM
struct ubus_object wireless_object;
struct ubus_object wps_object;
struct ubus_object dsl_object;
struct ubus_object port_object;
struct ubus_object system_object;
struct ubus_object dropbear_object;
struct ubus_object usb_object;
