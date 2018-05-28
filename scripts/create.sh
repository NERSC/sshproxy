#!/bin/sh

source url.conf
read -p "Username: " user
if [ -z $user ] ; then
  user=$USER
fi
read -p "Password: " -s pass
echo ""
#echo "$user $pass"
if [ $# -eq 0 ] ; then
  curl  -X POST -H "Authorization: Basic $user:$pass" $URL/create_pair
else
  curl  -X POST -d "{\"skey\": \"$2\"}" -H "Authorization: Basic $user:$pass" $URL/create_pair/$1/
fi
