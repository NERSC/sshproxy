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

class SSHAuthTestCase(unittest.TestCase):

    def setUp(self):
        self.ssh = ssh_auth.SSHAuth()
        self.user = 'blah'
        self.registry = MongoClient()['sshauth']['registry']

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
        p = self.ssh.create_pair(self.user, None)
        self.assertIsNotNone(p)
        k = self.get_all()
        self.assertEquals(len(k), 1)

    def test_get(self):
        """
        Test basic key retreival
        """
        p = self.ssh.create_pair(self.user, None)
        self.assertIsNotNone(p)
        k = self.get_pub(self.user, 'default')
        keys = self.ssh.get_keys(self.user, 'default')
        self.assertIn(k, keys)

    def test_scope(self):
        """
        Test that scopes work.
        """
        p = self.ssh.create_pair(self.user, None)
        self.assertIsNotNone(p)
        p2 = self.ssh.create_pair(self.user, 'bogus')
        self.assertIsNotNone(p)
        k = self.get_pub(self.user, 'bogus')
        keys = self.ssh.get_keys(self.user, 'bogus')
        self.assertIn(k, keys)
        keys = self.ssh.get_keys(self.user, 'default')
        self.assertNotIn(k, keys)


if __name__ == '__main__':
    unittest.main()
