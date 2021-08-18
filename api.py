#!/usr/bin/python


"""
SSH Proxy (sshproxy), Copyright (c) 2019, The Regents of the University of California, 
through Lawrence Berkeley National Laboratory (subject to receipt of any required 
approvals from the U.S. Dept. of Energy).  All rights reserved.
 
If you have questions about your rights to use or distribute this software, 
please contact Berkeley Lab's Intellectual Property Office at  IPO@lbl.gov.
 
NOTICE.  This Software was developed under funding from the U.S. Department of Energy 
and the U.S. Government consequently retains certain rights. As such, the U.S. 
Government has been granted for itself and others acting on its behalf a paid-up, 
nonexclusive, irrevocable, worldwide license in the Software to reproduce, distribute 
copies to the public, prepare derivative works, and perform publicly and display 
publicly, and to permit other to do so. 

See LICENSE for full text.
"""

from flask import Flask, request, Response
import logging
from ssh_auth import SSHAuth, ScopeError, CollabError
from pam import authenticate
import os
import json
import sys
from jwt import decode, PyJWTError

app = Flask(__name__)
CONFIG = os.environ.get('CONFIG', 'config.yaml')
JWT_PUB = os.environ.get("JWT_PUB")
ssh_auth = SSHAuth(CONFIG)
jwt_pub = None
_VERSION = "1.2.6"

if JWT_PUB is not None and os.path.exists(JWT_PUB):
    with open(JWT_PUB) as f:
        jwt_pub = f.read()

if 'SERVER_SOFTWARE' in os.environ:
    # Make flask logging work with gunicorn
    logname = 'gunicorn.error'
    gunicorn_error_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers.extend(gunicorn_error_logger.handlers)
else:
    logname = 'sshproxy'
app.logger.debug('Initializing api')

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


def get_target_user(request):
    try:
        rqd = request.get_data()
        data = json.loads(rqd)
        if 'target_user' in data:
            return data['target_user']
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

def jwt_auth(tok):
    if jwt_pub is None:
        raise AuthError("JWT not configured")
    try:
        pack = decode(tok[7:], key=jwt_pub, verify=True, algorithms='RS256')
    except PyJWTError:
        print("Failed to verify JWT")
        raise AuthError("JWT verify failed")

    if 'user' not in pack:
        raise AuthError("User not encoded in JWT")
    
    return pack['user']

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
    elif "Authorization" in request.headers:
        tok = request.headers['Authorization']
        if tok.startswith('Bearer '):
            username = jwt_auth(tok)
            return ctx('jwt', username)
        else:
            raise AuthError("Unknown auth method")
    else:
        raise AuthError("Authentication required")

        # This should eventually get dropped
        # (username, password) = legacyauth()
        # if username is None or password is None:
        #     raise AuthError("Username and password required")
        # authmode = 'legacy'

    if ssh_auth.check_failed_count(username):
        raise AuthError('Too many failed logins %s' % (username))
    if not authenticate(username, password, service='sshauth'):
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
        target_user = get_target_user(request)
        raddr = request.remote_addr
        putty = False
        if 'putty' in request.args:
            putty = True
        resp, cert = ssh_auth.create_pair(user, raddr, scope, skey=skey,
                                          target_user=target_user,
                                          putty=putty)
        app.logger.info('created %s' % (user))
        return resp + cert
    except AuthError as err:
        return auth_failure(str(err))
    except OSError as err:
        app.logger.warning('raised OSError %s' % str(err))
        return str(err), 403
    except CollabError as err:
        app.logger.warning('CollabError: %s' % str(err))
        return str(err), 403
    except ScopeError as err:
        app.logger.warning('Bad scope specified %s' % str(err))
        return str(err), 404
    except:
        return failure('create_pair_scope')


@app.route('/create_pair', methods=['POST'])
def create_pair():
    """
    Create an RSA key pair and return the private key
    """
    try:
        ctx = doauth()
        putty = False
        if 'putty' in request.args:
            putty = True
        raddr = request.access_route[-1]
        app.logger.info('raddr is %s' % raddr)
        resp, cert = ssh_auth.create_pair(ctx.username, raddr, None,
                                          putty=putty)
        app.logger.info('created %s' % (ctx.username))
        if cert is None:
            return resp
        else:
            return resp + cert
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
    except ScopeError as err:
        app.logger.warning('Bad scope specified %s' % str(err))
        return str(err), 404
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
