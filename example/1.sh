#!/bin/bash

echo "Status: 302 Redirect"
echo "location: /2.sh"
echo
exit 0

echo "Status: 200 OK"
echo "Content-type: text/plain"
echo
echo "On est dans un shell: "
echo "QUERY_STRING=${QUERY_STRING}"
echo "REQUEST_METHOD=${REQUEST_METHOD}"
echo "REQUEST_URI=${REQUEST_URI}"
echo "DOCUMENT_ROOT=${DOCUMENT_ROOT}"
echo "HTTP_HOST=${HTTP_HOST}"
echo "SCRIPT_FILENAME=${SCRIPT_FILENAME}"
echo "SERVER_SOFTWARE=${SERVER_SOFTWARE}"
echo "CONTENT_LENGTH=${CONTENT_LENGTH}"
echo "CONTENT_TYPE=${CONTENT_TYPE}"
echo "SCRIPT_NAME=${SCRIPT_NAME}"

echo
echo "BODY:"
if [ 0${CONTENT_LENGTH} -gt 0 ] ; then
	cat
	echo
	env
fi
