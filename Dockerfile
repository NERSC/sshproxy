FROM python:2.7

ENV DEBIAN_FRONTEND=noninteractive
ADD requirements.txt /tmp/requirements.txt
RUN apt-get -y update && apt-get -y install nslcd libpam-dev && pip install -r /tmp/requirements.txt

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


ADD . /src/
RUN cp /src/sshauth.pam /etc/pam.d/sshauth

ENV PYTHONPATH=/src/
# Start gunicorn
EXPOSE 5000
CMD ["/src/entrypoint.sh"]

