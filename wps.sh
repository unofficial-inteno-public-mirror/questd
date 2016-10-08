#!/bin/sh

. /usr/share/libubox/jshn.sh

case "$1" in
	list)
	echo '{ "status":{}, "pbc":{}, "pbc_client":{}, "genpin":{}, "checkpin":{"pin":"str"}, "stapin":{"pin":"str"}, "setpin":{"pin":"str"}, "showpin":{}, "stop":{} }'
	;;
	call)
		case "$2" in
			pbc|pbc_client|stapin|setpin|stop)
				read input
				ubus call router.wps $2 "$input"
				json_init
				json_dump
			;;
			*)
				read input
				ubus call router.wps $2 "$input"
			;;
		esac
	;;
esac

