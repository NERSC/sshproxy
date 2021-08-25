FROM python:3.8-buster

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get -y install nslcd libpam-dev vim putty-tools

# LDAP
ADD ldap /tmp/ldap
RUN \
    mkdir -p  /etc/httpd/ssl && \
    cp /tmp/ldap/ldap.conf /etc/ldap/ldap.conf && \
    cp /tmp/ldap/nslcd.conf /etc/nslcd.conf && \
    cp /tmp/ldap/nsswitch.conf /etc/nsswitch.conf && \
    cp /tmp/ldap/pam_ldap.conf /etc/pam_ldap.conf

# Install linotp
RUN \
   git clone https://github.com/LinOTP/linotp-auth-pam && \
   cd linotp-auth-pam && sh ./autogen.sh && ./configure && \
   make && cp src/.libs/*.so /lib/x86_64-linux-gnu/security/ && cd .. && rm -rf linotp-auth-pam

# Install pam_mfa
RUN \ 
   apt-get -y update && apt-get -y install libldap-dev && \
   git clone https://github.com/nersc/pam_mfa && \
   cd pam_mfa && sed -i 's/-lldap/-lldap -lpam/' Makefile && \
   sed -i 's|putenv|//putenv|' pam_mfa.c && \
   make && cp *.so /lib/x86_64-linux-gnu/security/

ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

ADD . /src/
RUN cp /src/sshauth.pam /etc/pam.d/sshauth

ENV PYTHONPATH=/src/
# Start gunicorn
EXPOSE 5000
CMD ["/src/entrypoint.sh"]

