from pymongo import MongoClient, MongoReplicaSetClient
import sys
import os
import os.path
import socket
from subprocess import call, Popen, PIPE
from time import time
import yaml
import tempfile
import grp


class ScopeError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class CollabError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class PrivError(Exception):
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
        self.default_scope = 'default'
        self.debug_on = False
        if 'DEBUG' in os.environ:
            self.debug_on = True

        mongo_host = 'localhost'
        if 'mongo_host' in os.environ:
            mongo_host = os.environ['mongo_host']
        if mongo_host.startswith('mongodb://'):
            (user, passwd, hosts, replset, authdb) = \
                self.parse_mongo_url(mongo_host)
            print('user=%s host=%s replset=%s authdb=%s' % (user, hosts, replset, authdb))
            mongo = MongoReplicaSetClient(hosts, replicaset=replset)
        else:
            mongo = MongoClient(mongo_host)
            user = None
            passwd = None
        self.db = mongo['sshauth']
        if user is not None and passwd is not None and user != '':
            self.db.authenticate(user, passwd, source=authdb)
        self.registry = self.db['registry']

    def debug(self, line):  # pragma: no cover
        if self.debug_on:
            print(line)

    def reload_config(self):
        sd = os.stat(self.configfile)
        mtime = sd.st_mtime
        if mtime == self.lastconfig:
            return
        if self.lastconfig is not None:
            print("Re-loading config")
        self.config = yaml.load(open(self.configfile), Loader=yaml.FullLoader)
        gconfig = self.config.get('global', {})
        self.unallowed_users = gconfig.get('unallowed_users', ['root'])
        self.scopes = self.config['scopes']
        for scopen in self.scopes:
            scope = self.scopes[scopen]
            scope['scopename'] = scopen
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
        out = None
        if not self.debug_on:
            out = open("/dev/null", "wb")
        self.debug('_run_command(): %s' % command)
        try:
            errno = call(command, stdout=out, stderr=out)
        except Exception as err:
            print(err)
            return -1
        return errno

    def _check_scope(self, scope, user, raddr, skey):
        if scope is None:
            raise ScopeError("No scope defined")
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
        """
        This is to check if the user is unallowed (e.g. root)
        """
        self.debug("_check_allowed()")
        if user in self.unallowed_users:
            raise OSError("user %s not allowed" % (user))
        # TODO: Add scope version too
        return True

    def _check_collaboration_account(self, target_user, user):
        """
        Check that the user is a member of the collaboration group
        and is therefore allowed to use the collab acount.

        TODO: Make the group name format a parameter.
        """
        try:
            return user in grp.getgrnam('c_%s' % target_user).gr_mem
        except:
            self.debug("Missing group c_%s" % target_user)
            return False

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
            raise ValueError("Unrecognized lifetime")

    def _sign(self, fn, principle, serial, scope):
        if scope is None:
            return None
        sn = scope['scopename']
        self.debug("_sign(%s,%s,%s,%s)" % (fn, principle, serial, sn))
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

    def _generate_pair(self, user, serial=None, scope=None, target_user=None,
                       putty=False):
        self.debug("_generate_pair(%s, %s, %s)" % (user, serial, scope))
        privfile = self.tmp_filename()
        pubfile = privfile + '.pub'
        self.debug("privfile=%s pubfile=%s" % (privfile, pubfile))
        if os.path.isfile(pubfile):
            raise OSError("file %s already exists" % pubfile)
        comment = user
        if target_user is not None:
            comment += ' as %s' % (target_user)
        if serial is not None:
            comment += ' serial:%s' % (serial)
        command = ['ssh-keygen', '-q', '-f', privfile, '-N', '', '-t', 'rsa',
                   '-m', 'PEM', '-C', comment]
        self.debug("command: %s" % command)
        cert = None
        if self._run_command(command) != 0:
            self.debug("command failed %s" % (' '.join(command)))
            raise OSError('Key generation failed')
        self.debug("ran command")
        with open(pubfile, 'r') as f:
            self.debug("opening %s" % pubfile)
            pub = f.read().rstrip()
        with open(privfile, 'r') as f:
            self.debug("opening %s" % privfile)
            priv = f.read()
        if target_user is None:
            cert = self._sign(privfile, user, serial, scope)
        else:
            cert = self._sign(privfile, target_user, serial, scope)
        ppk = None
        if putty:
            ppkfile = self.tmp_filename()
            command = ['puttygen', privfile, '-o', ppkfile]
            if self._run_command(command) != 0:
                raise OSError('Putty failed')
            with open(ppkfile) as f:
                ppk = f.read()
            os.remove(ppkfile)

        os.remove(privfile)
        os.remove(pubfile)
        pair = {
            'public': pub,
            'private': priv,
            'cert': cert,
            'ppk': ppk
        }
        # return pub, priv, cert, ppk
        return pair

    def _get_host_key(self, raddr, type='rsa'):
        command = ['ssh-keyscan', '-t', type, '-T', '5', raddr]
        p = Popen(command, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        errno = p.wait()
        if errno != 0 or len(stdout) < 2:
            raise OSError("ssh-keyscan failed")
        out = ' '.join(stdout.decode('utf-8').rstrip().split(' ')[1:])
        return out

    def _get_serial(self):
        return str(time()).replace('.', '')

    def _get_scope(self, scopename):
        if scopename is None:
            raise ScopeError("Scope is required.")
        if scopename not in self.scopes:
            raise ScopeError("Unrecognized scope")
        return self.scopes[scopename]

    def get_ca_pubkey(self, scopen):
        scope = self._get_scope(scopen)
        with open(scope['cacert']+'.pub') as f:
            cacert = f.read()
        return cacert

    def sign_host(self, raddr, scopen):
        scope = self._get_scope(scopen)
        if 'type' not in scope or scope['type'] != 'host':
            raise ScopeError("Scope must be a host type for this operaiton")
        lifetime = scope['lifetime_secs']
        pub = self._get_host_key(raddr)
        hostname = socket.gethostbyaddr(raddr)[0]
        fn = 'host'
        with open(fn+'.pub', 'w') as f:
            f.write(pub)
        serial = self._get_serial()
        cert = self._sign(fn, hostname, serial, scope)
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

    def create_pair(self, user, raddr, scopename, skey=None,
                    target_user=None, lifetime=LIFETIME,
                    putty=False):
        self.debug("create_pair()")
        self.reload_config()
        if scopename is not None:
            self.debug("scope is %s" % scopename)
        else:
            scopename = self.default_scope
        scope = self._get_scope(scopename)
        self._check_scope(scope, user, raddr, skey)
        if 'lifetime_secs' in scope:
            lifetime = scope['lifetime_secs']
        if 'collaboration' in scope and scope['collaboration']:
            self.debug("Using collab")
            if target_user is None:
                raise ScopeError("Missing required target_user")
            if not self._check_collaboration_account(target_user, user):
                raise CollabError("User %s not a member of %s" %
                                  (user, target_user))
        else:
            target_user = None

        self._check_allowed(user, scopename)
        serial = self._get_serial()
        self.debug("serial is %s" % serial)
        pair = self._generate_pair(user, serial=serial,
                                   scope=scope,
                                   putty=putty,
                                   target_user=target_user)
        self.debug("past _generate_pair()")
        rec = {'principle': user,
               'pubkey': pair['public'],
               'type': 'user',
               'enabled': True,
               'scope': scope['scopename'],
               'serial': serial,
               'created': time(),
               'expires': time() + lifetime
               }
        if target_user is not None:
            rec['target_user'] = target_user
        if 'allowed_targets' in scope:
            rec['allowed_targets'] = scope['allowed_targets']
        self.registry.insert(rec)
        if putty:
            return pair['ppk'], ''
        else:
            return pair['private'], pair['cert']

    def get_keys(self, user, scopename=None, ip=None):
        resp = []
        now = time()
        q = {'principle': user, 'enabled': True}
        if scopename is not None:
            self._get_scope(scopename)
            q['scope'] = scopename

        for rec in self.registry.find(q):
            if now > rec['expires']:
                self.expire(rec['_id'])
            elif 'target_user' in rec:
                # Skip target_user records since this
                # would mean it is a collab key
                continue
            elif 'allowed_targets' in rec and ip not in rec['allowed_targets']:
                continue
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

        q = {'target_user': user, 'enabled': True}

        for rec in self.registry.find(q):
            if now > rec['expires']:
                self.expire(rec['_id'])
            elif 'allowed_targets' in rec and ip not in rec['allowed_targets']:
                continue
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

    def revoke_key(self, request_user, serial):
        if request_user not in self.config['global']['admin_users']:
            raise PrivError("unallowed user: %s" % (request_user))
        up = {'$set': {'enabled': False}}
        resp = self.registry.update({'serial': serial}, up)
        if resp['nModified'] > 0:
            return True
        else:
            return False

    def revoked(self):
        """
        Return a list of disabled keys that aren't expired.
        """
        now = time()
        resp = ""
        for k in self.registry.find({'enabled': False, 'expires': {"$gt": now}}):
            resp += '%s\n' % (k['pubkey'])
        return resp


def main():  # pragma: no cover
    s = SSHAuth('config.yaml')
    if len(sys.argv) > 2 and sys.argv[1] == 'create':
        user = sys.argv[2]
        scope = None
        if len(sys.argv) > 3:
            scope = sys.argv[2]
        priv = s.create_pair(user, scope)
        print(priv)
    elif len(sys.argv) > 2 and sys.argv[1] == 'getkeys':
        user = sys.argv[2]
        scope = None
        if len(sys.argv) > 3:
            scope = sys.argv[2]
        keys = s.get_keys(user, scope=scope)
        for k in keys:
            print(k)
    elif len(sys.argv) > 2 and sys.argv[1] == 'expireall':
        user = sys.argv[2]
        s.expireall(user)


if __name__ == '__main__':
    main()
