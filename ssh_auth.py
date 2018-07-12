from pymongo import MongoClient
import sys
import os
import subprocess
from time import time
import yaml
import tempfile


class SSHAuth(object):
    """
    This class handles most of the backend work for the image gateway.
    It uses a Mongo Database to track state, uses threads to dispatch work,
    and has public functions to lookup, pull and expire images.
    """

    # Default Lifetime 1 day
    LIFETIME = 3600*24

    def __init__(self, configfile):
        """
        Create an instance of the ssh Auth manager.
        """
        self.config = yaml.load(open(configfile))
        self.scopes = self.config['scopes']
        for scopen in self.scopes:
            scope = self.scopes[scopen]
            if 'lifetime' in scope:
                scope['lifetime_secs'] = self._convert_time(scope['lifetime'])
                print scope['lifetime_secs']

        mongo_host = 'localhost'
        if 'mongo_host' in os.environ:
            mongo_host = os.environ['mongo_host']
        mongo = MongoClient(mongo_host)
        self.db = mongo['sshauth']
        self.registry = self.db['registry']

    def _run_command(self, command):
        try:
            errno = subprocess.call(command)
        except Exception as err:
            print err
            return -1
        return errno

    def _check_scope(self, rscope, user, raddr, skey):
        if rscope is None:
            return True
        if rscope not in self.scopes:
            raise ValueError("Unrecongnized Scope.")
        scope = self.scopes[rscope]
        if 'skey' in scope and skey != scope['skey']:
            raise OSError("skey doesn't match")
        if 'allowed_create_addrs' in scope and \
           raddr not in scope['allowed_create_addrs']:
            raise OSError("host not in allowed host for scope")
        return True

    def _convert_time(self, ltime):
        # If a number, then it is in minutes
        if type(ltime) is int:
            return 60*ltime
        elif ltime[-1] >= '0' and ltime[-1] <= '9':
            return 60*int(ltime)
        elif ltime.endswith('d'):
            return 24*3600*int(ltime[0:-1])
        elif ltime.endswith('w'):
            return 7*24*3600*int(ltime[0:-1])
        elif ltime.endswith('y'):
            return 365*24*3600*int(ltime[0:-1])
        else:
            raise ValueError("Unrecongnized lifetime")

    def _sign(self, fn, user, scopename):
        if scopename is None:
            return None
        scope = self.scopes.get(scopename)
        if scope is None:
            return None
        if 'cacert' not in scope:
            return None
        comm = ['ssh-keygen', '-s', scope['cacert'],
                '-I', 'user_%s' % (user),
                '-n', user]
        if 'lifetime_secs' in scope:
            comm.append('-V')
            comm.append('+' + str(scope['lifetime_secs']))
        comm.append(fn+'.pub')
        if self._run_command(comm) != 0:
            raise OSError('Signing failed')
        with open(fn+'-cert.pub', 'r') as f:
            cert = f.read().rstrip()
        os.remove(fn + '-cert.pub')
        return cert

    def tmp_filename(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        return f.name
    	
    def _generate_pair(self, user, scope=None):
        privfile = tmp_filename()
        pubfile = tmp_filename()
        comm = ['ssh-keygen', '-q', '-f', privfile, '-N', '', '-t', 'rsa']
        cert = None
        if self._run_command(comm) != 0:
            raise OSError('Key generation failed')
        with open(pubfile, 'r') as f:
            pub = f.read().rstrip()
        with open(privfile, 'r') as f:
            priv = f.read()
        cert = self._sign(fname, user, scope)

        os.remove(privfile)
        os.remove(pubfile)
        return pub, priv, cert

    def create_pair(self, user, raddr, scope, skey=None, lifetime=LIFETIME):
        if scope is not None:
            self._check_scope(scope, user, raddr, skey)
            if 'lifetime_secs' in self.scopes[scope]:
                lifetime = self.scopes[scope]['lifetime_secs']
        pub, priv, cert = self._generate_pair(user, scope=scope)
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
        return priv, cert

    def get_keys(self, user, scope=None):
        resp = []
        now = time()
        q = {'user': user, 'enabled': True}
        if scope is not None:
            q['scope'] = scope
        for rec in self.registry.find(q):
            if now > rec['expires']:
                self.expire(rec['_id'])
            else:
                resp.append(rec['pubkey'])
        return resp

    def expireall(self, user):
        self.registry.remove({'user': user})


def main(): # pragma: no cover
    s = SSHAuth('config.yaml')
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
