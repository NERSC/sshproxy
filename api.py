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


app = Flask(__name__)

ssh_auth = SSHAuth()


@app.before_first_request
def setup_logging():
    """
    Initialize variables
    """
    if not app.debug:
        # In production mode, add log handler to sys.stderr.
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(logging.INFO)


def auth(username, password):
    """
    Perform authentication
    """
    return pam.authenticate(username, password, service='sshauth')


@app.route('/create_pair', methods=['POST'])
def create_pair():
    """
    Create an RSA key pair and return the private key
    """
    try:
        headers = request.headers
        if 'Authorization' not in headers:
            return "No authentiation provided", 404
        authh = headers['Authorization']
        if authh.startswith('Basic '):
            (username, password) = authh.replace('Basic ', '').split(':')
            if not auth(username, password):
                return "Permission denied", 404
        else:
            return "No authentiation provided", 404
        resp = ssh_auth.create_pair(username, None)
        return resp
    except:
        raise
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
        headers = request.headers
        if 'Authorization' not in headers:
            return "No authentiation provided", 404
        authh = headers['Authorization']
        if authh.startswith('Basic '):
            (username, password) = authh.replace('Basic ', '').split(':')
            if not auth(username, password):
                return "Permission denied", 404
        else:
            return "No authentiation provided", 404
        ssh_auth.expireall(username)
        return "Success"
    except:
        return "Failure", 401
