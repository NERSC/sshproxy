#!/usr/bin/python


"""
SSH Auth API, Copyright (c) 2017, The Regents of the University of California,
through Lawrence Berkeley National Laboratory (subject to receipt of any
required approvals from the U.S. Dept. of Energy).  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
 3. Neither the name of the University of California, Lawrence Berkeley
    National Laboratory, U.S. Dept. of Energy nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.`

See LICENSE for full text.
"""

from flask import Flask, request, Response
import logging
from ssh_auth import SSHAuth
import pam
import os
import json
import sys

app = Flask(__name__)
app.debug = True
CONFIG = os.environ.get('CONFIG', 'config.yaml')
ssh_auth = SSHAuth(CONFIG)
_VERSION = "1.1"


class ctx(object):
    def __init__(self, type, username):
        self.type = type
        self.username = username


class AuthError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


@app.before_first_request
def setup_logging():
    """
    Initialize variables
    """
    if not app.debug:
        # In production mode, add log handler to sys.stderr.
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(logging.INFO)
    else:
        app.logger.addHandler(logging.StreamHandler(sys.stdout))
        app.logger.setLevel(logging.DEBUG)


def get_skey(request):
    try:
        rqd = request.get_data()
        data = json.loads(rqd)
        if 'skey' in data:
            return data['skey']
    except:
        return None
    return None


def legacyauth():
    """
    Support legacy auth for a limited time.
    """
    # Try legacy
    if 'Authorization' not in request.headers:
        return (None, None)
    authh = request.headers['Authorization']
    if not authh.startswith('Basic '):
        return (None, None)
    astr = authh.split(' ')[1]
    (username, password) = astr.split(':')
    return (username, password)


def doauth():
    """
    Authenticaiton function.  This currently just supports basic auth using
    pam.
    """
    auth = request.authorization
    if auth is not None:
        if auth.username is None or auth.password is None:
            raise AuthError("Username and password required")
        username = auth.username
        password = auth.password
        authmode = 'basic'
    else:
        # This should eventually get dropped
        (username, password) = legacyauth()
        if username is None or password is None:
            raise AuthError("Username and password required")
        authmode = 'legacy'

    if ssh_auth.check_failed_count(username):
        raise AuthError('Too many failed logins %s' % (username))
    if os.environ.get('FAKEAUTH') == "1":
        app.logger.warning("Fake Auth: %s" % (username))
        if password == 'bad':
            ssh_auth.failed_login(username)
            raise AuthError('Bad fake password')
        authmode = 'fake'
    elif not pam.authenticate(username, password, service='sshauth'):
        ssh_auth.failed_login(username)
        raise AuthError("Failed login: %s" % (username))
    ssh_auth.reset_failed_count(username)
    return ctx(authmode, username)


def auth_failure(mess='FailedLogin'):
    """Sends a 401 response that enables basic auth"""
    app.logger.warning('Authentication Failure (%s).' % (mess))
    return Response(
        'Authentication failed. %s\n'
        'Please provide a proper credential' % (mess), 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def failure(funcname):
    """Sends a 404"""
    app.logger.warning('Unexpcted failure in %s.' % (funcname))
    return Response(
        'Request failed unexpectedly\n', 500)


@app.route('/create_pair/<scope>/', methods=['POST'])
def create_pair_scope(scope):
    """
    Create an RSA key pair and return the private key
    """
    try:
        ctx = doauth()
        user = ctx.username
        skey = get_skey(request)
        raddr = request.remote_addr
        resp, cert = ssh_auth.create_pair(user, raddr, scope, skey=skey)
        app.logger.info('created %s' % (user))
        return resp + cert
    except AuthError as err:
        return auth_failure(str(err))
    except OSError as err:
        app.logger.warning('raised OSError %s' % str(err))
        return str(err), 403
    except ValueError as err:
        app.logger.warning('raised ValueError %s' % str(err))
        return str(err), 403
    except:
        return failure('create_pair_scope')


@app.route('/create_pair', methods=['POST'])
def create_pair():
    """
    Create an RSA key pair and return the private key
    """
    try:
        ctx = doauth()
        raddr = request.access_route[-1]
        app.logger.info('raddr is %s' % raddr)
        resp = ssh_auth.create_pair(ctx.username, raddr, None)
        app.logger.info('created %s' % (ctx.username))
        return resp
    except AuthError as err:
        return auth_failure(str(err))
    except:
        return failure('create_pair')


@app.route('/sign_host/<scope>/', methods=['POST'])
def sign_host(scope):
    """
    Create an RSA key pair and return the private key
    """
    try:
        raddr = request.access_route[-1]
        cert = ssh_auth.sign_host(raddr, scope)
        app.logger.info('signed %s' % (raddr))
        return cert
    except:
        return failure('sign_host')


@app.route('/get_ca_pubkey/<scope>/', methods=['GET'])
def get_ca_pubkey(scope):
    """
    Used to retrieve the CA key for a scopeself.
    """
    try:
        return ssh_auth.get_ca_pubkey(scope)
    except:
        return failure('get_ca_pubkey')


@app.route('/get_keys/<username>', methods=['GET'])
def get_keys(username):
    """
    Get the keys for a user
    """
    try:
        app.logger.info('get keys for %s' % (username))
        keys = ssh_auth.get_keys(username, None)
        mess = ''
        for k in keys:
            mess += k + '\n'
        return mess
    except:
        return failure('get_keys')


@app.route('/get_keys/<scope>/<username>', methods=['GET'])
def get_keys_scope(scope, username):
    """
    Get the keys for a user
    """
    try:
        app.logger.info('get keys for %s in %s' % (username, scope))
        keys = ssh_auth.get_keys(username, scope)
        mess = ''
        for k in keys:
            mess += k + '\n'
        return mess
    except:
        return failure('get_keys_scope')


@app.route('/reset', methods=['DELETE'])
def reset():
    """
    Get the keys for a user
    """
    try:
        ctx = doauth()
        ssh_auth.expireuser(ctx.username)
        app.logger.info('resetting %s' % (ctx.username))
        return "Success"
    except AuthError as err:
        return auth_failure(str(err))
    except:
        return failure('reset')


# Return the version
@app.route('/version', methods=['GET'])
def version():
    return _VERSION


# for the load balancer checks
@app.route('/status.html', methods=['GET'])
def status():
    return "OK"
