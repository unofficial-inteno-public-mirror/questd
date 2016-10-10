#!/bin/sh

. /usr/share/libubox/jshn.sh

case "$1" in
        list)
                echo '{ "status" : {} }'
        ;;
        call)
                case "$2" in
                        status)
                                json_init
                                json_add_string state "$(ip route | grep -q default && echo ok || echo off)"
                                json_dump
                        ;;
                esac
        ;;
esac

