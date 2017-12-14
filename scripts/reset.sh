#!/bin/sh

source url.conf

read -p "Username: " user
if [ -z $user ] ; then
  user=$USER
fi
read -p "Password: " -s pass
echo "" 
#echo "$user $pass"
curl  -X DELETE -H "Authorization: Basic $user:$pass" $URL/reset

