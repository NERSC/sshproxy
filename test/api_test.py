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
from time import time
from base64 import b64encode
from mock import MagicMock
from jwt import encode
import logging

def versiontuple(v):
    return tuple(map(int, (v.split("."))))


def _my_run(com):
    if com[0] == 'ssh-keygen' and com[1] == '-q':
        fname = com[3]
        with open(fname, "w") as f:
            f.write('bogus')
        with open(fname+'.pub', "w") as f:
            f.write('bogus')
    if com[0] == 'ssh-keygen' and com[1] == '-s':
        fname = com[-1].replace('.pub', '-cert.pub')
        with open(fname, "w") as f:
            f.write('bogus')
        with open(fname+'.pub', "w") as f:
            f.write('bogus')
    elif com[0] == 'puttygen':
        fname = com[3]
        with open(fname, "w") as f:
            f.write('ppk')
    return 0


def _my_auth(user, password, service=''):
    if password == 'bad':
        return False
    else:
        return True


class APITestCase(unittest.TestCase):

    def setUp(self):
        test_dir = os.path.dirname(os.path.abspath(__file__)) + "/../test/"
        self.test_dir = test_dir
        import api
        self.api = api
        self.api.authenticate = MagicMock(side_effect=_my_auth)
        self.app = api.app.test_client()
        self.api.app.logger.setLevel(logging.ERROR)

        self.headers = self.make_header('auser:password')
        self.badheaders = self.make_header('auser:bad')
        bstr = b64encode(b'auser:bad').decode('utf-8')

        self.badmethod = {'Authorization': 'Blah ' + bstr}
        self.api.ssh_auth.failed_count = {}
        jwtkf=os.path.join(test_dir, 'jwtRS256.key')
        with open(jwtkf) as f:
            self.jwt_key = f.read()
        jwtkf=os.path.join(test_dir, 'jwtRS256bad.key')
        with open(jwtkf) as f:
            self.jwt_bad_key = f.read()

    def make_header(self, authstr):
        encoded = b64encode(authstr.encode()).decode('utf-8')
        return {'Authorization': 'Basic %s' % (encoded) }

    def get_all(self):
        r = []
        for rec in self.registry.find():
            r.append(rec)
        return r

    def get_pub(self, user, scope):
        r = self.registry.find_one({'user': user, 'scope': scope})
        return r['pubkey']

    def test_status(self):
        rv = self.app.get('/status.html', headers=self.headers)
        self.assertEquals(rv.data, b"OK")

    def test_version(self):
        rv = self.app.get('/version', headers=self.headers)
        self.assertGreater(versiontuple(rv.data.decode("utf-8")), versiontuple("0.9.0"))

    def test_create_pair(self):
        rv = self.app.post('/create_pair', headers=self.headers)
        self.assertEquals(rv.status_code, 200)

        rv = self.app.post('/create_pair', headers=self.badheaders)
        self.assertEquals(rv.status_code, 401)

        rv = self.app.post('/create_pair', headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)
        # Missing auth
        rv = self.app.post('/create_pair')
        self.assertEquals(rv.status_code, 401)

        # Raise an unexpected error
        old = self.api.ssh_auth.create_pair
        self.api.ssh_auth.create_pair = MagicMock(side_effect=KeyError())
        rv = self.app.post('/create_pair', headers=self.headers)
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.create_pair = old


    def test_jwt(self):
        jwt = encode({'user': 'auser'}, self.jwt_key, algorithm='RS256')
        h = {'Authorization': 'Bearer %s' % (jwt)}
        rv = self.app.post('/create_pair', headers=h)
        self.assertEqual(rv.status_code, 200)

        jwt = encode({'user': 'auser'}, self.jwt_bad_key, algorithm='RS256')
        h = {'Authorization': 'Bearer %s' % (jwt)}
        rv = self.app.post('/create_pair', headers=h)
        self.assertEqual(rv.status_code, 401)

    def test_create_pair_putty(self):
        old = self.api.ssh_auth._run_command
        self.api.ssh_auth._run_command = MagicMock(side_effect=_my_run)
        rv = self.app.post('/create_pair?putty', headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        self.assertTrue(rv.data.decode('utf-8').startswith('ppk'))

        data = '{"skey": "scope1-secret"}'
        url = '/create_pair/scope1/?putty'
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        self.assertTrue(rv.data.decode('utf-8').startswith('ppk'))
        self.api.ssh_auth._run_command = old

    def test_get_ca_pubkey(self):
        rv = self.app.get('/get_ca_pubkey/scope3/')
        self.assertEquals(rv.status_code, 200)
        self.assertIsNotNone(rv.data)

        # Raise an unexpected error
        old = self.api.ssh_auth.get_ca_pubkey
        self.api.ssh_auth.get_ca_pubkey = MagicMock(side_effect=KeyError())
        rv = self.app.get('/get_ca_pubkey/scope3/')
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.get_ca_pubkey = old

    def test_sign_host(self):
        rv = self.app.post('/sign_host/scope3/')
        self.assertEquals(rv.status_code, 200)

        # Raise an unexpected error
        old = self.api.ssh_auth.sign_host
        self.api.ssh_auth.sign_host = MagicMock(side_effect=KeyError())
        rv = self.app.post('/sign_host/scope3/')
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.sign_host = old

    def test_get_keys_scope(self):
        data = '{"skey": "scope1-secret"}'
        url = '/create_pair/scope1/'
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.get('/get_keys/scope1/auser')
        self.assertEquals(rv.status_code, 200)
        self.assertIn(b'auser', rv.data)
        self.assertIn(b'ssh-rsa', rv.data)
        rv = self.app.get('/get_keys/bogus/auser')
        self.assertEquals(rv.status_code, 404)
        rv = self.app.get('/get_keys/scope3/auser')
        self.assertEquals(rv.status_code, 200)
        self.assertEquals(b'', rv.data)

        # Raise an unexpected error
        old = self.api.ssh_auth.get_keys
        self.api.ssh_auth.get_keys = MagicMock(side_effect=KeyError())
        rv = self.app.get('/get_keys/scope1/auser')
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.get_keys = old

    def test_create_pair_scope(self):
        data = '{"skey": "scope1-secret"}'
        url = '/create_pair/scope1/'
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.post(url, data=data, headers=self.badheaders)
        self.assertEquals(rv.status_code, 401)
        rv = self.app.post(url, data=data, headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)

        # No data
        rv = self.app.post(url, headers=self.headers)
        self.assertEquals(rv.status_code, 403)
        # No skey
        rv = self.app.post(url, data='{"a": "b"}', headers=self.headers)
        self.assertEquals(rv.status_code, 403)
        # Bad Scope
        url = '/create_pair/bogus/'
        rv = self.app.post(url, headers=self.headers)
        self.assertEquals(rv.status_code, 404)

        # Raise an unexpected error
        old = self.api.ssh_auth.create_pair
        self.api.ssh_auth.create_pair = MagicMock(side_effect=KeyError())
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.create_pair = old

    def test_create_pair_collab(self):
        data = '{"target_user": "tuser"}'
        url = '/create_pair/scope5/'
        # Mock _check_collaboration_account because we don't
        # want to modify any groups
        old = self.api.ssh_auth._check_collaboration_account
        self.api.ssh_auth._check_collaboration_account = \
            MagicMock(return_value=True)
        # Happy test.  Make sure that the key indicates it is for the
        # test user
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        self.assertIn(b'auser as tuser', rv.data)
        # Missing target_user should return a 404
        rv = self.app.post(url, headers=self.headers)
        self.assertEquals(rv.status_code, 404)
        # User not in group should return a 403
        self.api.ssh_auth._check_collaboration_account = \
            MagicMock(return_value=False)
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 403)
        # reset things
        self.api.ssh_auth._check_collaboration_account = old

    def test_get_keys(self):
        rv = self.app.get('/get_keys/auser')
        self.assertEquals(rv.status_code, 200)
        rv = self.app.get('/get_keys/buser')
        self.assertEquals(rv.status_code, 200)

        # Raise an unexpected error
        old = self.api.ssh_auth.get_keys
        self.api.ssh_auth.get_keys = MagicMock(side_effect=KeyError())
        rv = self.app.get('/get_keys/auser')
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.get_keys = old

    def test_reset(self):
        rv = self.app.delete('/reset', headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.delete('/reset', headers=self.badheaders)
        self.assertEquals(rv.status_code, 401)
        rv = self.app.delete('/reset', headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)

        # Raise an unexpected error
        old = self.api.ssh_auth.expireuser
        self.api.ssh_auth.expireuser = MagicMock(side_effect=KeyError())
        rv = self.app.delete('/reset', headers=self.headers)
        self.assertEquals(rv.status_code, 500)
        self.api.ssh_auth.expireuser = old

    def test_revoke(self):
        """
        Test revoking a key.
        """
        self.api.ssh_auth.registry.remove({})
        # Generate a key
        data = '{"skey": "scope1-secret"}'
        url = '/create_pair/scope1/'
        rv = self.app.post(url, data=data, headers=self.headers)
        keyv = rv.data.decode('utf-8').split('\n')[-1].split(' ')[-1]
        serial = keyv.split(':')[-1]
        # Create a key for a non-admin user
        jwt = encode({'user': 'auser'}, self.jwt_key, algorithm='RS256')
        hauser = {'Authorization': 'Bearer %s' % (jwt.decode('utf-8'))}

        # Create a key for an admin user
        jwt = encode({'user': 'admin'}, self.jwt_key, algorithm='RS256')
        hadmin = {'Authorization': 'Bearer %s' % (jwt.decode('utf-8'))}


        # Try revoking as regular user
        rv = self.app.post('/revoke/%s' % (serial), headers=hauser)
        self.assertEquals(rv.status_code, 401)
        # Check key is still valid
        act_keys = self.app.get('/get_keys/auser').data.decode('utf-8')
        self.assertIn(serial, act_keys)
        revoked = self.app.get('/revoked').data.decode('utf-8')
        self.assertNotIn(serial, revoked)

        # Try revoking as a real user
        rv = self.app.post('/revoke/%s' % (serial), headers=hadmin)
        self.assertEquals(rv.status_code, 200)

        # Confirm key is gone
        act_keys = self.app.get('/get_keys/auser').data.decode('utf-8')
        self.assertNotIn(serial, act_keys)
        revoked = self.app.get('/revoked').data.decode('utf-8')
        self.assertIn(serial, revoked)


    def test_failed_count(self):
        """
        Test Failed Count Logic
        """
        u = 'auser'
        uri = '/create_pair'
        fc = self.api.ssh_auth.failed_count
        # Confirm it fails if user is over max and in window
        with self.api.app.test_request_context(uri, headers=self.headers):
            rv = self.api.doauth()
        fc[u] = {'count': 5, 'last': time()}
        with self.api.app.test_request_context(uri, headers=self.headers):
            with self.assertRaises(self.api.AuthError):
                rv = self.api.doauth()
        # Confirm it works if a good login happens after the window
        fc[u] = {'count': 5, 'last': time()-600}
        with self.api.app.test_request_context(uri, headers=self.headers):
            rv = self.api.doauth()
        self.assertNotIn(u, fc)
        self.assertIsNotNone(rv)
        # Confirm it works if a good login happens under the max
        fc[u] = {'count': 4, 'last': time()}
        with self.api.app.test_request_context(uri, headers=self.headers):
            rv = self.api.doauth()
        self.assertIsNotNone(rv)
        self.assertNotIn(u, fc)
        # Confirm failed count increments
        fc[u] = {'count': 4, 'last': time()}
        with self.api.app.test_request_context(uri, headers=self.badheaders):
            before = time()
            with self.assertRaises(self.api.AuthError):
                rv = self.api.doauth()
            self.assertEquals(fc[u]['count'], 5)
            self.assertGreaterEqual(int(fc[u]['last']), int(before))
        fc = {}


if __name__ == '__main__':
    unittest.main()
