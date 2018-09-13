# sshauth, Copyright (c) 2015, The Regents of the University of California,
# through Lawrence Berkeley National Laboratory (subject to receipt of any
# required approvals from the U.S. Dept. of Energy).  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#  3. Neither the name of the University of California, Lawrence Berkeley
#     National Laboratory, U.S. Dept. of Energy nor the names of its
#     contributors may be used to endorse or promote products derived from this
#     software without specific prior written permission.`
#
# See LICENSE for full text.

import os
import unittest
import ssh_auth
from pymongo import MongoClient
from time import time
from ssh_auth import ScopeError
from tempfile import mkstemp
import yaml

_localhost = '127.0.0.1'


class SSHAuthTestCase(unittest.TestCase):

    def setUp(self):
        test_dir = os.path.dirname(os.path.abspath(__file__)) + "/../test/"
        self.test_dir = test_dir
        self.ssh = ssh_auth.SSHAuth(test_dir+'/config.yaml')
        self.user = 'blah'
        self.registry = MongoClient()['sshauth']['registry']
        self.registry.remove()
        self.host = os.environ.get('TESTIP', _localhost)

    def get_all(self):
        r = []
        for rec in self.registry.find():
            r.append(rec)
        return r

    def get_pub(self, user, scope):
        r = self.registry.find_one({'principle': user, 'scope': scope})
        return r['pubkey']

    def test_create(self):
        """
        Test create keys
        """
        self.registry.remove({})
        p = self.ssh.create_pair(self.user, _localhost, None)
        self.assertIsNotNone(p)
        k = self.get_all()
        self.assertEquals(len(k), 1)

    def test_cleanup(self):
        """
        Test create keys
        """
        with open('tempfile', 'w') as f:
            f.write('blah')
        p = self.ssh.create_pair(self.user, _localhost, None)
        self.assertIsNotNone(p)

    def test_get(self):
        """
        Test basic key retreival
        """
        p = self.ssh.create_pair(self.user, _localhost, None)
        self.assertIsNotNone(p)
        k = self.get_pub(self.user, 'default')
        keys = self.ssh.get_keys(self.user, 'default')
        self.assertIn(k, keys)

    def test_scope(self):
        """
        Test that scopes work.
        """
        scope1 = 'scope1'
        scope2 = 'scope2'
        secret = 'scope1-secret'
        p = self.ssh.create_pair(self.user, _localhost, None)
        self.assertIsNotNone(p)
        p2 = self.ssh.create_pair(self.user, _localhost, scope1, skey=secret)
        self.assertIsNotNone(p2)
        k = self.get_pub(self.user, scope1)
        keys = self.ssh.get_keys(self.user, scope1)
        self.assertIn(k, keys)
        keys = self.ssh.get_keys(self.user, 'default')
        self.assertNotIn(k, keys)
        p = self.ssh.create_pair(self.user, _localhost, scope2)
        self.assertIsNotNone(p)
        with self.assertRaises(OSError):
            p = self.ssh.create_pair(self.user, _localhost, 'scope4')

    def test_check_scope(self):
        p = self.ssh._check_scope(None, 'auser', _localhost, None)
        self.assertTrue(p)
        p = self.ssh._check_scope('scope4', 'auser', _localhost, None)
        self.assertTrue(p)
        with self.assertRaises(OSError):
            p = self.ssh._check_scope('scope4', 'buser', _localhost, None)

    def test_allowed(self):
        p = self.ssh._check_allowed('auser', None)
        self.assertTrue(p)
        with self.assertRaises(OSError):
            p = self.ssh._check_allowed('root', None)
        with self.assertRaises(OSError):
            p = self.ssh.create_pair('root', _localhost, None)

    def test_expiration_storage(self):
        slop = 1
        DAY = 24*3600
        scope2 = 'scope2'
        now = time()
        # Cleanup everything
        self.registry.remove()
        p = self.ssh.create_pair(self.user, _localhost, scope2)
        self.assertIsNotNone(p)
        rec = self.registry.find_one()
        exp = rec['expires']
        self.assertGreaterEqual(exp, now + DAY - slop)
        self.assertLess(exp, now + DAY + slop)

    def test_autoexpire(self):
        rec = {'principle': 'auser',
               'pubkey': 'bogus1',
               'type': 'user',
               'enabled': True,
               'scope': 'default',
               'serial': 'bogus1',
               'created': time(),
               'expires': time() - 100
               }
        rec1 = self.registry.insert(rec)
        rec = {'principle': 'auser',
               'pubkey': 'bogus2',
               'type': 'user',
               'enabled': True,
               'scope': 'default',
               'serial': 'bogus2',
               'created': time(),
               'expires': time() + 100
               }
        rec2 = self.registry.insert(rec)
        p = self.ssh.get_keys('auser')
        self.assertIn('bogus2', p)
        self.assertNotIn('bogus1', p)
        up = self.registry.find_one({'_id': rec1})
        self.assertFalse(up['enabled'])
        up = self.registry.find_one({'_id': rec2})
        self.assertTrue(up['enabled'])

    def test_scope_errors(self):
        """
        Test that scopes work.
        """
        scope1 = 'scope1'
        scope2 = 'scope2'
        with self.assertRaises(OSError):
            self.ssh.create_pair(self.user, _localhost, scope1, skey='wrong')
        with self.assertRaises(ScopeError):
            self.ssh.create_pair(self.user, _localhost, 'bogus', skey='wrong')
        # This is a bogus address that should fail
        with self.assertRaises(OSError):
            self.ssh.create_pair(self.user, '127.0.0.2', scope2)
        with self.assertRaises(ScopeError):
            self.ssh.get_ca_pubkey(None)
        with self.assertRaises(ScopeError):
            self.ssh.get_ca_pubkey('bogus')
        with self.assertRaises(ScopeError):
            self.ssh.sign_host('127.0.0,1', None)
        with self.assertRaises(ScopeError):
            self.ssh.sign_host('127.0.0,1', 'bogus')
        with self.assertRaises(ScopeError):
            self.ssh.sign_host('127.0.0,1', scope1)

    def test_expire_conversion(self):
        """
        Test conversions
        """
        slop = 2
        DAY = 24*3600
        WEEK = 7*DAY
        YEAR = 365*DAY
        e = self.ssh._convert_time(1)
        self.assertGreaterEqual(e, 60)
        self.assertLess(e, 60+slop)
        # Minutes as a string
        e = self.ssh._convert_time('1')
        self.assertGreaterEqual(e, 60)
        self.assertLess(e, 60+slop)
        # Days
        e = self.ssh._convert_time('1d')
        self.assertGreaterEqual(e, DAY)
        self.assertLess(e, DAY+slop)
        # weeks
        e = self.ssh._convert_time('1w')
        self.assertGreaterEqual(e, WEEK)
        self.assertLess(e, WEEK + slop)
        # years
        e = self.ssh._convert_time('1y')
        self.assertGreaterEqual(e, YEAR)
        self.assertLess(e, YEAR+slop)
        with self.assertRaises(ValueError):
            self.ssh._convert_time('1x')

    def test_get_host_key(self):
        """
        Test _get_host_key
        """
        # Get the key for cori01-224
        pub = self.ssh._get_host_key(self.host)
        self.assertEquals(pub[0:7], 'ssh-rsa')

        # Test against a bogus host
        with self.assertRaises(OSError):
            self.ssh._get_host_key('127.0.0.2')

    def test_sign_host(self):
        """
        Test _get_host_key
        """
        # Get the key for cori01-224
        self.registry.remove({})
        cert = self.ssh.sign_host(self.host, 'scope3')
        self.assertIsNotNone(cert)
        rec = self.registry.find_one()
        self.assertIsNotNone(rec)
        self.assertIn('serial', rec)
        self.assertIn('principle', rec)
        self.assertIn('type', rec)
        self.assertEquals(rec['type'], 'host')

    def test_failed_count(self):
        """
        Test Failed Count Logic
        """
        u = 'auser'
        # Confirm it fails if user is over max and in window
        self.ssh.failed_count[u] = {'count': 5, 'last': time()}
        self.assertTrue(self.ssh.check_failed_count(u))

        # Confirm reset clears things
        self.ssh.reset_failed_count(u)
        self.assertNotIn(u, self.ssh.failed_count)
        self.assertFalse(self.ssh.check_failed_count(u))

        # Confirm it works if a good login happens after the window
        self.ssh.failed_count[u] = {'count': 5, 'last': time()-600}
        self.assertFalse(self.ssh.check_failed_count(u))

        # Confirm it works if a good login happens under the max
        self.ssh.failed_count[u] = {'count': 4, 'last': time()}
        self.assertFalse(self.ssh.check_failed_count(u))

        # Confirm failed count increments
        self.ssh.failed_count[u] = {'count': 4, 'last': time()}
        before = time()
        self.ssh.failed_login(u)
        self.assertEquals(self.ssh.failed_count[u]['count'], 5)
        self.assertGreaterEqual(self.ssh.failed_count[u]['last'], before)
        self.ssh.failed_count = {}

    def test_reload(self):
        """
        Test Reloading Config
        """
        fh, cfile = mkstemp()
        nscope = 'newscope'
        conf = yaml.load(open(self.test_dir+'/config.yaml'))
        with open(cfile, "w") as outfile:
            yaml.dump(conf, outfile, default_flow_style=False)
        ssh = ssh_auth.SSHAuth(cfile)
        self.assertNotIn(nscope, ssh.scopes)
        with self.assertRaises(ScopeError):
            ssh.create_pair(self.user, _localhost, nscope)
        # Add a test trying to create in newscope
        conf['scopes'][nscope] = {'lifetime': '2y'}
        with open(cfile, "w") as outfile:
            yaml.dump(conf, outfile, default_flow_style=False)
        ssh.create_pair(self.user, _localhost, nscope)
        self.assertIn(nscope, ssh.scopes)
        # Add a test to create in newscope
        del conf['scopes'][nscope]
        with open(cfile, "w") as outfile:
            yaml.dump(conf, outfile, default_flow_style=False)
        with self.assertRaises(ScopeError):
            ssh.create_pair(self.user, _localhost, nscope)
        os.remove(cfile)


if __name__ == '__main__':
    unittest.main()
