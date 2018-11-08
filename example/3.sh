#!/bin/sh

if [ "X${HTTP_AUTHORIZATION}" = "X" ] ; then
	echo 'Status: 401'
	echo 'WWW-Authenticate: Basic realm="Credentials"'
	echo
	exit 0
elif [ "${HTTP_AUTHORIZATION}" != "Basic YWRtaW46YWRtaW4=" ] ; then
	echo 'Status: 401'
	echo 'WWW-Authenticate: Basic realm="Wrong Credentials"'
	echo "X-test: ${HTTP_AUTHORIZATION}"
	echo
	exit 0
fi

echo 'Content-type: text/plain'
echo

echo 'It works!'
echo "X-test: ${HTTP_AUTHORIZATION}|"
