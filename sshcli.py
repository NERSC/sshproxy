#!/usr/bin/env python

import requests
import os
from getpass import getpass, getuser
import sys
import argparse
from json import dumps
from requests.auth import HTTPBasicAuth

# Defaults
URL = "https://sshauthapi.nersc.gov"
OUTPUT = os.environ['HOME'] + '/.ssh/nersc'
MAXRETRY = 3


def parse_args():
    parser = argparse.ArgumentParser(description='Request an ssh key pair ' +
                                     'from an ssh proxy server')
    parser.add_argument('--scope', '-s', help='name of scope')
    parser.add_argument('--debug', '-d', help='additional debug',
                        action='store_true')
    parser.add_argument('--key', '-k', help='prompt for skey',
                        action='store_true')
    parser.add_argument('--url', dest='url', help='url for service',
                        default=URL)
    parser.add_argument('--user', '-u', help='username',
                        default=getuser())
    parser.add_argument('--output', '-o', help='output file name',
                        default=OUTPUT)
    return parser.parse_args()


def error(message):
    sys.stderr.write(message + '\n')
    sys.exit(1)


def write_output(data, output):
    cert = None
    with open(output, 'w') as f:
        os.chmod(output, 0o600)
        for line in data.split('\n'):
            if line.startswith('ssh-rsa-cert'):
                cert = line
                break
            f.write(line+'\n')

    if cert is not None:
        print("Writing cert")
        with open(output+'-cert.pub', 'w') as f:
            f.write(cert+'\n')


def main():
    args = parse_args()
    data = None
    user = args.user
    output = args.output
    url = args.url + '/create_pair'
    if args.scope is not None:
        url += '/%s/' % (args.scope)
    retry = 0

    if args.key:
        skey = getpass('skey: ')
        data = dumps({'skey': skey})

    while (retry < MAXRETRY):
        pwd = getpass()
        if args.debug:
            print(url)
        resp = requests.post(url, auth=HTTPBasicAuth(user, pwd), data=data)
        if resp.status_code != 200:
            retry += 1
            print(resp.text)
        else:
            break

    if retry == MAXRETRY:
        error("Max retries.  Exiting.")

    try:
        write_output(resp.text, output)
    except:
        error('Error saving output.')
    print("Success.  Key saved in %s" % (output))


if __name__ == '__main__':
    main()
