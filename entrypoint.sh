#!/bin/sh



if [ ! -z "$OTP_PROXY_URL" ] ; then
  echo "Replacing OTP Proxy with $OTP_PROXY_URL"
  sed -i "s|https://otpproxy.nersc.gov|$OTP_PROXY_URL|" /etc/pam.d/sshauth
fi

if [ ! -z "$LDAP_BASE" ] ; then
  echo "Replacing LDAP BASE with $LDAP_BASE"
  sed -i "s/ou=nim-ldap,ou=host,o=ldapsvc,dc=nersc,dc=gov/${LDAP_BASE}/" /etc/nslcd.conf
  sed -i "s/ou=nim-ldap,ou=host,o=ldapsvc,dc=nersc,dc=gov/${LDAP_BASE}/" /etc/pam_ldap.conf
  sed -i "s/ou=cori,ou=Host,o=ldapsvc,dc=nersc,dc=gov/${LDAP_BASE}/" /etc/pam.d/sshauth
fi

nslcd &

[ -z $WORKERS ] && export WORKERS=5

[ -z $LOG_LEVEL ] && export LOG_LEVEL=INFO


/usr/local/bin/gunicorn --workers $WORKERS --timeout 60 -b 0.0.0.0:5000 --log-level $LOG_LEVEL api:app
