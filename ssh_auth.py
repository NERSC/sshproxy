from pymongo import MongoClient
import sys
import os
import subprocess
from time import time


class SSHAuth(object):
    """
    This class handles most of the backend work for the image gateway.
    It uses a Mongo Database to track state, uses threads to dispatch work,
    and has public functions to lookup, pull and expire images.
    """

    LIFETIME = 3600*24

    def __init__(self):
        """
        Create an instance of the ssh Auth manager.
        """
        mongo_host = 'localhost'
        if 'mongo_host' in os.environ:
            mongo_host = os.environ['mongo_host']
        mongo = MongoClient(mongo_host)
        self.db = mongo['sshauth']
        self.registry = self.db['registry']

    def run_command(self, command):
        try:
            errno = subprocess.call(command)
        except Exception as err:
            print err
            return -1
        return errno

    def generate_pair(self):
        fname = 'tempfile'
        comm = ['ssh-keygen', '-q', '-f', fname, '-N', '', '-t', 'rsa']
        if self.run_command(comm) != 0:
            print "Error"
            return False
        with open(fname+'.pub', 'r') as f:
            pub = f.read().rstrip()
        with open(fname, 'r') as f:
            priv = f.read()
        os.remove(fname)
        os.remove(fname+'.pub')
        return pub, priv

    def create_pair(self, user, scope, lifetime=LIFETIME):
        pub, priv = self.generate_pair()
        if scope is None:
            scope = 'default'
        rec = {'user': user,
               'pubkey': pub,
               'enabled': True,
               'scope': scope,
               'created': time(),
               'expires': time() + lifetime
               }
        self.registry.insert(rec)
        return priv

    def get_keys(self, user, scope=None):
        resp = []
        q = {'user': user, 'enabled': True}
        if scope is not None:
            q['scope'] = scope
        for rec in self.registry.find(q):
            resp.append(rec['pubkey'])
        return resp

    def expireall(self, user):
        self.registry.remove({'user': user})


def main():
    s = SSHAuth()
    if len(sys.argv) > 2 and sys.argv[1] == 'create':
        user = sys.argv[2]
        scope = None
        if len(sys.argv) > 3:
            scope = sys.argv[2]
        priv = s.create_pair(user, scope)
        print priv
    elif len(sys.argv) > 2 and sys.argv[1] == 'getkeys':
        user = sys.argv[2]
        scope = None
        if len(sys.argv) > 3:
            scope = sys.argv[2]
        keys = s.get_keys(user, scope=scope)
        for k in keys:
            print k
    elif len(sys.argv) > 2 and sys.argv[1] == 'expireall':
        user = sys.argv[2]
        s.expireall(user)


if __name__ == '__main__':
    main()
