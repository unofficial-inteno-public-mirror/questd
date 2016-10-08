#!/bin/sh

. /usr/share/libubox/jshn.sh

case "$1" in
	list)
		echo '{ "info":{}, "filesystem":{}, "logs":{}, "networks":{}, "wl":{"vif":"str"}, "dslstats":{}, "clients":{}, "clients6":{}, "processes":{}, "igmptable":{}, "sta":{"vif":"str"}, "stas":{}, "ports":{"network":"str"}, "leases":{"network":"str","family":32}, "host":{"ipaddr":"str","macaddr":"str"}, "usb":{}, "radios":{}, "password_set":{"user":"str","password":"str","curpass":"str"}, "memory_bank":{"bank":32}, "reload":{}, "get_ssh_keys":{}, "add_ssh_key":{"path":"str"}, "del_ssh_key":{"path":"str"}, "linkspeed":{"interface":"str"} }'
	;;
	call)
		case "$2" in
			info)
				ubus call router.system info
			;;
			filesystem)
				ubus call router.system fs
			;;
			logs)
				ubus call router.system logs
			;;
			networks)
				ubus call router.network dump
			;;
			wl)
				read input
				ubus call router.wireless status "$input"
			;;
			dslstats)
				ubus call router.dsl stats
			;;
			clients)
				ubus call router.network clients '{"family":4}'
			;;
			clients6)
				ubus call router.network clients '{"family":6}'
			;;
			processes)
				ubus call router.system processes
			;;
			igmptable)
				ubus call router.net igmp_snooping
			;;
			sta|stas)
				read input
				ubus call router.wireless stas "$input"
			;;
			ports)
				read input
				ubus call router.network ports "$input"
			;;
			leases)
				read input
				ubus call router.network leases "$input"
			;;
			host)
				read input
				json_load "$input"
				json_get_var ipaddr ipaddr
				json_get_var macaddr macaddr
				ubus call router.network clients
			;;
			usb)
				ubus call router.usb status
			;;
			radios)
				ubus call router.wireless radios
			;;
			password_set)
				read input
				ubus call router.system password_set "$input"
				json_init
				json_dump
			;;
			memory_bank)
				read input
				json_load "$input"
				json_get_var bank bank
				if [ -n "$bank" ]; then
					ubus call router.system memory_bank "$input"
					json_init
					json_dump
				else
					ubus call router.system memory_bank
				fi
			;;
			reload)
				ubus call router.network reload
				json_init
				json_dump
			;;
			get_ssh_keys|add_ssh_key|del_ssh_key)
				read input
				ubus call router.dropbear "$2" "$input"
			;;
			linkspeed)
				read input
				json_load "$input"
				json_get_var interface interface
				json_cleanup

				json_load "$(ubus call router.port status "{'port':'$interface'}")"
				json_get_var type type
				json_get_var speed speed

				json_init
				json_add_string linktype "$type"
				json_add_string linkspeed "$speed"
				json_dump
			;;
		esac
	;;
esac

