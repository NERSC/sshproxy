#!/bin/sh

source url.conf

read -p "Username: " user
if [ -z $user ] ; then
  user=$USER
fi
curl  -X DELETE -u $user $URL/reset
