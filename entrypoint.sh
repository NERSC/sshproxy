#!/bin/sh



if [ ! -z "$LDAP_BASE" ] ; then
  echo "Replacing LDAP BASE with $LDAP_BASE"
  sed -i "s/ou=nim-ldap,ou=host,o=ldapsvc,dc=nersc,dc=gov/${LDAP_BASE}/" /etc/nslcd.conf
  sed -i "s/ou=nim-ldap,ou=host,o=ldapsvc,dc=nersc,dc=gov/${LDAP_BASE}/" /etc/pam_ldap.conf

fi

nslcd &

[ -z $WORKERS ] && export WORKERS=5

[ -z $LOG_LEVEL ] && export LOG_LEVEL=INFO


/usr/local/bin/gunicorn --workers $WORKERS --timeout 60 -b 0.0.0.0:5000 --log-level $LOG_LEVEL api:app
