#!/bin/sh

echo $FLAG > /flag
chown root:root /flag
chmod 644 /flag
export FLAG=
rm /start.sh

gunicorn -c gunicorn.py