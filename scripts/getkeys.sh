#!/bin/sh

source url.conf

if [ ! -z $1 ]; then
	USER=$1
fi
echo $URL/get_keys/$USER
curl  -X GET ${URL}/get_keys/$USER
