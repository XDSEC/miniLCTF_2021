#!/bin/sh
# Add your startup script

# DO NOT DELETE

# Dynamic flag generated by CTFd-whale
cd /home/ctf/bin
echo "flag = b'$FLAG'" > ./secret.py
chown root:ctf ./secret.py
chmod 640 ./secret.py
export FLAG=not_flag
FLAG=not_flag

python3 ./task.py
