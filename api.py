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

from flask import Flask, request
import logging
from ssh_auth import SSHAuth
import pam
import os
import json
from time import time

app = Flask(__name__)
CONFIG = os.environ.get('CONFIG', 'config.yaml')
ssh_auth = SSHAuth(CONFIG)


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


def get_skey(request):
    try:
        rqd = request.get_data()
        data = json.loads(rqd)
        if 'skey' in data:
            return data['skey']
    except:
        return None
    return None


def doauth(headers):
    """
    Authenticaiton function.  This currently just supports basic auth using
    pam.
    """
    if 'Authorization' not in headers:
        raise AuthError("No authentication provided")
    authh = headers['Authorization']
    if authh.startswith('Basic '):
        (username, password) = authh.replace('Basic ', '').split(':')
        if ssh_auth.check_failed_count(username):
            app.logger.warning('Too many failed logins %s' % (username))
            raise AuthError('Too many failed logins')
        if os.environ.get('FAKEAUTH') == "1":
            print "Fake Auth: %s" % (username)
            if password == 'bad':
                ssh_auth.failed_login(username)
                raise AuthError('Bad fake password')
            ssh_auth.reset_failed_count(username)
            return ctx('fake', username)
        elif not pam.authenticate(username, password, service='sshauth'):
            ssh_auth.failed_login(username)
            app.logger.warning('failed login %s' % (username))
            raise AuthError("Failed login")
        ssh_auth.reset_failed_count(username)
        return ctx('basic', username)
    else:
        raise ValueError("Unrecongnized authentication")


@app.route('/create_pair/<scope>/', methods=['POST'])
def create_pair_scope(scope):
    """
    Create an RSA key pair and return the private key
    """
    try:
        ctx = doauth(request.headers)
        user = ctx.username
        skey = get_skey(request)
        raddr = request.remote_addr
        resp, cert = ssh_auth.create_pair(user, raddr, scope, skey=skey)
        app.logger.info('created %s' % (user))
        return resp + cert
    except AuthError:
        return "Authentication Failure", 403
    except OSError as err:
        return str(err), 403
    except ValueError as err:
        return str(err), 403
    except:
        return "Failure", 401


@app.route('/create_pair', methods=['POST'])
def create_pair():
    """
    Create an RSA key pair and return the private key
    """
    try:
        ctx = doauth(request.headers)
        raddr = request.access_route[-1]
        resp = ssh_auth.create_pair(ctx.username, raddr, None)
        app.logger.info('created %s' % (ctx.username))
        return resp
    except AuthError:
        return "Authentication Failure", 403
    except:
        return "Failure", 401

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
        return "Failure", 401

@app.route('/get_ca_pubkey/<scope>/', methods=['GET'])
def get_ca_pubkey(scope):
    """
    Used to retrieve the CA key for a scopeself.
    """
    try:
        return ssh_auth.get_ca_pubkey(scope)
    except:
        return "Failure", 401


@app.route('/get_keys/<username>', methods=['GET'])
def get_keys(username):
    """
    Get the keys for a user
    """
    try:
        keys = ssh_auth.get_keys(username, None)
        mess = ''
        for k in keys:
            mess += k + '\n'
        return mess
    except:
        return "Failure", 401


@app.route('/reset', methods=['DELETE'])
def reset():
    """
    Get the keys for a user
    """
    try:
        ctx = doauth(request.headers)
        ssh_auth.expireuser(ctx.username)
        return "Success"
    except AuthError:
        return "Authentication Failure", 403
    except:
        return "Failure", 401
