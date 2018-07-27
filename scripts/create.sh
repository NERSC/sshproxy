#!/bin/sh

source url.conf
read -p "Username: " user
if [ -z $user ] ; then
  user=$USER
fi
if [ $# -eq 0 ] ; then
  curl  -X POST -u $user $URL/create_pair
else
  curl  -X POST -d "{\"skey\": \"$2\"}" -u $user $URL/create_pair/$1/
fi
