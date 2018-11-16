from pymongo import MongoClient, MongoReplicaSetClient
import sys
import os
import os.path
import socket
from subprocess import call, Popen, PIPE
from time import time
import yaml
import tempfile


class ScopeError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class SSHAuth(object):
    """
    This class handles most of the backend work for the api.
    It uses a Mongo Database to track state, uses threads to dispatch work,
    and has public functions to lookup, pull and expire images.
    """

    # Default Lifetime 1 day
    LIFETIME = 3600*24

    def __init__(self, configfile):
        """
        Create an instance of the ssh Auth manager.
        """
        self.configfile = configfile
        self.lastconfig = None
        self.reload_config()

        mongo_host = 'localhost'
        if 'mongo_host' in os.environ:
            mongo_host = os.environ['mongo_host']
        if mongo_host.startswith('mongodb://'):
            (user, passwd, hosts, replset, authdb) = \
                self.parse_mongo_url(mongo_host)
            print '%s %s %s %s' % (user, hosts, replset, authdb)
            mongo = MongoReplicaSetClient(hosts, replicaset=replset)
        else:
            mongo = MongoClient(mongo_host)
            user = None
            passwd = None
        self.db = mongo['sshauth']
        if user is not None and passwd is not None:
            self.db.authenticate(user, passwd, source=authdb)
        self.registry = self.db['registry']

    def reload_config(self):
        sd = os.stat(self.configfile)
        mtime = sd.st_mtime
        if mtime == self.lastconfig:
            return
        if self.lastconfig is not None:
            print("Re-loading config")
        self.config = yaml.load(open(self.configfile))
        gconfig = self.config.get('global', {})
        self.unallowed_users = gconfig.get('unallowed_users', ['root'])
        self.scopes = self.config['scopes']
        for scopen in self.scopes:
            scope = self.scopes[scopen]
            if 'lifetime' in scope:
                scope['lifetime_secs'] = self._convert_time(scope['lifetime'])
        self.failed_count = {}
        self.MAX_FAILED = gconfig.get('max_failed_logins', 5)
        self.MAX_FAILED_WINDOW = gconfig.get('max_failed_window', 60 * 5)
        self.lastconfig = mtime

    # mongodb://$muser:$mpass@$n1,$n2,$n3/?replicaSet=$replset
    def parse_mongo_url(self, url):
        url = url.replace('mongodb://', '')
        if '/?' in url:
            (p1, p2) = url.split('/?')
            arr = p2.split('=')
            replset = arr[1]
        else:
            replset = None
            p1 = url

        (userpasswd, hoststr) = p1.split('@')
        (user, passwd) = userpasswd.split(':', 1)
        authdb = 'admin'
        if '/' in hoststr:
            (hoststr, authdb) = hoststr.split('/')
        hosts = hoststr.split(',')
        return (user, passwd, hosts, replset, authdb)

    def check_failed_count(self, username):
        """
        Return True if the user has too many failed attempts.
        """
        if username not in self.failed_count:
            return False
        fr = self.failed_count[username]
        # Outside window
        if (time() - fr['last']) >= self.MAX_FAILED_WINDOW:
            del self.failed_count[username]
            return False
        # under max
        if fr['count'] < self.MAX_FAILED:
            return False
        return True

    def failed_login(self, username):
        if username not in self.failed_count:
            self.failed_count[username] = {'count': 0}
        self.failed_count[username]['count'] += 1
        self.failed_count[username]['last'] = time()

    def reset_failed_count(self, username):
        if username in self.failed_count:
            del self.failed_count[username]

    def _run_command(self, command):
        print '_run_command(): %s' % command
        try:
            errno = call(command)
        except Exception as err:
            print err
            return -1
        return errno

    def _check_scope(self, rscope, user, raddr, skey):
        if rscope is None:
            return True
        if rscope not in self.scopes:
            raise ScopeError("Invalid or missing Scope.")
        scope = self.scopes[rscope]
        if 'skey' in scope and skey != scope['skey']:
            raise OSError("skey doesn't match")
        if 'allowed_create_addrs' in scope and \
           raddr not in scope['allowed_create_addrs']:
            raise OSError("host not in allowed host for scope")
        if 'allowed_users' in scope and \
           user not in scope['allowed_users']:
            raise OSError("User not in allowed users for scope")
        return True

    def _check_allowed(self, user, scope):
        print "_check_allowed()"
        if user in self.unallowed_users:
            raise OSError("user %s not allowed" % (user))
        # TODO: Add scope version too
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
        elif ltime.endswith('m'):
            return 30*24*3600*int(ltime[0:-1])
        elif ltime.endswith('y'):
            return 365*24*3600*int(ltime[0:-1])
        else:
            raise ValueError("Unrecongnized lifetime")

    def _sign(self, fn, principle, serial, scopename):
        print "_sign(%s, %s, %s, %s)" % (fn, principle, serial, scopename)
        if scopename is None:
            return None
        scope = self.scopes.get(scopename)
        if scope is None:
            return None
        if 'cacert' not in scope:
            return None
        command = ['ssh-keygen', '-s', scope['cacert'], '-z', serial]
        if scope.get('type') == 'host':
            command.append('-h')
            pname = 'host_%s' % (principle)
        else:
            pname = 'user_%s' % (principle)
        command.extend(['-I', pname, '-n', principle])
        if scope is not None and 'allowed_hosts' in scope:
            allowed_hosts = scope['allowed_hosts']
            command.extend(['-O', 'source-address=' +
                            ','.join(allowed_hosts)])

        if 'lifetime_secs' in scope:
            command.append('-V')
            command.append('+' + str(scope['lifetime_secs']))
        command.append(fn+'.pub')
        if self._run_command(command) != 0:
            raise OSError('Signing failed')
        with open(fn+'-cert.pub', 'r') as f:
            cert = f.read().rstrip()
        os.remove(fn + '-cert.pub')
        return cert

    def tmp_filename(self):
        """
        Allocate a temporary filename and delete it.
        """
        f = tempfile.NamedTemporaryFile(delete=True)
        f.close()
        return f.name

    def _generate_pair(self, user, serial=None, scope=None):
        print "_generate_pair(%s, %s, %s)" % (user, serial, scope)
        privfile = self.tmp_filename()
        pubfile = privfile + '.pub'
        print "privfile=%s pubfile=%s" % (privfile, pubfile)
        if os.path.isfile(pubfile):
            raise OSError("file %s already exists" % pubfile)
        comment = user
        if serial is not None:
            comment += ' serial:%s' % (serial)
        command = ['ssh-keygen', '-q', '-f', privfile, '-N', '', '-t', 'rsa',
                   '-C', comment]
        print "command: %s" % command
        cert = None
        if self._run_command(command) != 0:
            print "raise OS error"
            raise OSError('Key generation failed')
        print "ran command"
        with open(pubfile, 'r') as f:
            print "opening %s" % pubfile
            pub = f.read().rstrip()
        with open(privfile, 'r') as f:
            print "opening %s" % privfile
            priv = f.read()
        cert = self._sign(privfile, user, serial, scope)

        os.remove(privfile)
        os.remove(pubfile)
        return pub, priv, cert

    def _get_host_key(self, raddr, type='rsa'):
        command = ['ssh-keyscan', '-t', type, '-T', '5', raddr]
        p = Popen(command, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        errno = p.wait()
        if errno != 0 or len(stdout) < 2:
            raise OSError("ssh-keyscan failed")
        out = ' '.join(stdout.rstrip().split(' ')[1:])
        return out

    def _get_serial(self):
        return str(time()).replace('.', '')

    def get_ca_pubkey(self, scopen):
        if scopen is None:
            raise ScopeError("Scope is required.")
        if scopen not in self.scopes:
            raise ScopeError("Unrecongnized scope")
        scope = self.scopes[scopen]
        with open(scope['cacert']+'.pub') as f:
            cacert = f.read()
        return cacert

    def sign_host(self, raddr, scopen):
        if scopen is None:
            raise ScopeError("Scope is required for host signing")
        if scopen not in self.scopes:
            raise ScopeError("Unrecongnized scope")
        scope = self.scopes[scopen]
        if 'type' not in scope or scope['type'] != 'host':
            raise ScopeError("Scope must be a host type for this operaiton")
        lifetime = scope['lifetime_secs']
        pub = self._get_host_key(raddr)
        hostname = socket.gethostbyaddr(raddr)[0]
        fn = 'host'
        with open(fn+'.pub', 'w') as f:
            f.write(pub)
        serial = self._get_serial()
        cert = self._sign(fn, hostname, serial, scopen)
        os.remove(fn+'.pub')
        rec = {'ip': raddr,
               'principle': hostname,
               'type': 'host',
               'pubkey': pub,
               'enabled': True,
               'serial': serial,
               'scope': scopen,
               'created': time(),
               'expires': time() + lifetime
               }
        self.registry.insert(rec)
        return cert

    def create_pair(self, user, raddr, scope, skey=None, lifetime=LIFETIME):
        print "create_pair()"
        self.reload_config()
        if scope is not None:
            print "scope is %s" % scope
            self._check_scope(scope, user, raddr, skey)
            if 'lifetime_secs' in self.scopes[scope]:
                lifetime = self.scopes[scope]['lifetime_secs']
        self._check_allowed(user, scope)
        serial = self._get_serial()
        print "serial is %s" % serial
        pub, priv, cert = self._generate_pair(user, serial=serial, scope=scope)
        print "past _generate_pair()"
        if scope is None:
            scope = 'default'
        rec = {'principle': user,
               'pubkey': pub,
               'type': 'user',
               'enabled': True,
               'scope': scope,
               'serial': serial,
               'created': time(),
               'expires': time() + lifetime
               }
        self.registry.insert(rec)
        return priv, cert

    def get_keys(self, user, scope=None):
        resp = []
        now = time()
        q = {'principle': user, 'enabled': True}
        if scope is not None:
            if scope not in self.scopes:
                raise ScopeError()
            q['scope'] = scope

        for rec in self.registry.find(q):
            if now > rec['expires']:
                self.expire(rec['_id'])
            else:
                kscope = rec['scope']
                allowed_hosts = None
                if 'allowed_hosts' in self.scopes[kscope]:
                    allowed_hosts = self.scopes[kscope]['allowed_hosts']
                pubkey = rec['pubkey']
                if allowed_hosts is not None:
                    allowstring = 'from="%s"' % (','.join(allowed_hosts))
                    pubkey = '%s %s' % (allowstring, pubkey)
                resp.append(pubkey)
        return resp

    def expire(self, id):
        up = {'$set': {'enabled': False}}
        self.registry.update({'_id': id}, up)

    def expireuser(self, user):
        up = {'$set': {'enabled': False}}
        self.registry.update({'principle': user}, up)


def main():  # pragma: no cover
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
