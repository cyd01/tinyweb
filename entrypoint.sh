#!/bin/sh
echo "TINYWEB_PORT=${TINYWEB_PORT}"
PORT=${TINYWEB_PORT:-80}
if [ ! -d /www ] ; then
	mkdir /www
fi
/bin/tinyweb /www ${PORT}
