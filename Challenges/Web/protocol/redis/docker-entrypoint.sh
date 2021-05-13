#!/bin/bash
echo $FLAG > /flag
export FLAG=flag_not_here
FLAG=flag_not_here
rm -f /flag.sh

service apache2 start
redis-server /usr/src/redis-3.2.11/redis.conf
