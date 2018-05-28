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


class SSHAuthTestCase(unittest.TestCase):

    def setUp(self):
        test_dir = os.path.dirname(os.path.abspath(__file__)) + "/../test/"
        self.test_dir = test_dir
        self.ssh = ssh_auth.SSHAuth(test_dir+'/config.yaml')
        self.user = 'blah'
        self.registry = MongoClient()['sshauth']['registry']
        self.registry.remove()

    def get_all(self):
        r = []
        for rec in self.registry.find():
            r.append(rec)
        return r

    def get_pub(self, user, scope):
        r = self.registry.find_one({'user': user, 'scope': scope})
        return r['pubkey']

    def test_create(self):
        """
        Test create keys
        """
        self.registry.remove({})
        p = self.ssh.create_pair(self.user, '127.0.0.1', None)
        self.assertIsNotNone(p)
        k = self.get_all()
        self.assertEquals(len(k), 1)

    def test_cleanup(self):
        """
        Test create keys
        """
        with open('tempfile', 'w') as f:
            f.write('blah')
        p = self.ssh.create_pair(self.user, '127.0.0.1', None)
        self.assertIsNotNone(p)

    def test_get(self):
        """
        Test basic key retreival
        """
        p = self.ssh.create_pair(self.user, '127.0.0.1', None)
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
        p = self.ssh.create_pair(self.user, '127.0.0.1', None)
        self.assertIsNotNone(p)
        p2 = self.ssh.create_pair(self.user, '127.0.0.1', scope1, skey=secret)
        self.assertIsNotNone(p2)
        k = self.get_pub(self.user, scope1)
        keys = self.ssh.get_keys(self.user, scope1)
        self.assertIn(k, keys)
        keys = self.ssh.get_keys(self.user, 'default')
        self.assertNotIn(k, keys)
        p = self.ssh.create_pair(self.user, '127.0.0.1', scope2)
        self.assertIsNotNone(p)

    def test_check_scope(self):
        p = self.ssh._check_scope(None, 'auser', '127.0.0.1', None)
        self.assertTrue(p)

    def test_expiration_storage(self):
        slop = 1
        DAY = 24*3600
        scope2 = 'scope2'
        now = time()
        # Cleanup everything
        self.registry.remove()
        p = self.ssh.create_pair(self.user, '127.0.0.1', scope2)
        self.assertIsNotNone(p)
        rec = self.registry.find_one()
        exp = rec['expires']
        self.assertGreaterEqual(exp, now + DAY - slop)
        self.assertLess(exp, now + DAY + slop)

    def test_scope_errors(self):
        """
        Test that scopes work.
        """
        scope1 = 'scope1'
        scope2 = 'scope2'
        with self.assertRaises(OSError):
            self.ssh.create_pair(self.user, '127.0.0.1', scope1, skey='wrong')
        with self.assertRaises(ValueError):
            self.ssh.create_pair(self.user, '127.0.0.1', 'bogus', skey='wrong')
        with self.assertRaises(OSError):
            self.ssh.create_pair(self.user, '127.0.0.2', scope2)

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


if __name__ == '__main__':
    unittest.main()
