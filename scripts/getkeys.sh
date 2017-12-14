#!/bin/sh

source url.conf

echo $URL
USER=$1
curl  -X GET ${URL}/get_keys/$1
