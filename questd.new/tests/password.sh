#!/bin/sh

# test router.os.password

#set -x

# ubus list router.os.*
# ubus call router.os.password set '{"user":"","password":"newpassword","":""}'

user="testuser"
password="password0"

#clean before test
grep -q $user /etc/shadow && deluser $user

# add test user to the system
adduser -H -D $user || { echo adduser -H -D $user failed; exit; }
echo -e "password\npassword\n" | passwd $user >/dev/null

ubus list router* | grep -q password || { echo ubus: router.os.password not found; exit; }

ubus list -v router.os.password | grep -q set || { echo ubus: set method not found; exit; }

# change to same password
ubus call router.os.password set \
	"{\"user\":\"$user\",\"password\":\"password\",\"newpassword\":\"password\"}" \
|| { echo router.os.password set $user password failed; exit; }

# change to another password
ubus call router.os.password set \
	"{\"user\":\"$user\",\"password\":\"password\",\"newpassword\":\"password0\"}" \
|| { echo router.os.password set $user password0 failed; exit; }

#check memory usage
memory=$(ps w | grep "\./questd" | grep -v grep | awk '{print $3}')
for i in `seq 1 100`; do
	# one iteration: 100ms
	ubus call router.os.password set \
	"{\"user\":\"$user\",\"password\":\"$password\",\"newpassword\":\"password$i\"}" \
	|| echo router.os.password set $user $password password$i failed;
	password="password$i"
done
memory2=$(ps w | grep "\./questd" | grep -v grep | awk '{print $3}')

[ "$memory" == "$memory2" ] || { echo "memory before $memory"; echo "memory after $memory2"; }

# remove test user from system
deluser $user || { echo deluser failed; exit; }

echo ok
#set +x
