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


class APITestCase(unittest.TestCase):

    def setUp(self):
        os.environ['FAKEAUTH'] = '1'
        test_dir = os.path.dirname(os.path.abspath(__file__)) + "/../test/"
        self.test_dir = test_dir
        import api
        self.api = api
        self.app = api.app.test_client()
        self.headers = self.make_header('auser:password')
        self.badheaders = self.make_header('auser:bad')
        self.badmethod = {'Authorization': 'Blah ' + b64encode('auser:bad')}
        self.leggood = {'Authorization': 'Basic auser:good'}
        self.legbad = {'Authorization': 'Basic auser:bad'}
        self.api.ssh_auth.failed_count = {}

    def make_header(self, authstr):
        return {'Authorization': 'Basic '+b64encode(authstr)}

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
        self.assertEquals(rv.data, "OK")

    def test_version(self):
        rv = self.app.get('/version', headers=self.headers)
        self.assertGreater(float(rv.data), 0.9)

    def test_create_pair(self):
        rv = self.app.post('/create_pair', headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.post('/create_pair', headers=self.badheaders)
        self.assertEquals(rv.status_code, 401)
        print rv.data
        rv = self.app.post('/create_pair', headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)
        # Missing auth
        rv = self.app.post('/create_pair')
        self.assertEquals(rv.status_code, 401)
        # Legacy auth
        rv = self.app.post('/create_pair', headers=self.leggood)
        self.assertEquals(rv.status_code, 200)
        # Legacy bad auth
        rv = self.app.post('/create_pair', headers=self.legbad)
        self.assertEquals(rv.status_code, 401)

    def test_get_ca_pubkey(self):
        rv = self.app.get('/get_ca_pubkey/scope3/')
        self.assertEquals(rv.status_code, 200)
        self.assertIsNotNone(rv.data)

    def test_sign_host(self):
        rv = self.app.post('/sign_host/scope3/')
        self.assertEquals(rv.status_code, 200)

    def test_pam(self):
        del os.environ['FAKEAUTH']
        rv = self.app.post('/create_pair', headers=self.headers)
        self.assertEquals(rv.status_code, 401)
        os.environ['FAKEAUTH'] = '1'

    def test_get_keys_scope(self):
        data = '{"skey": "scope1-secret"}'
        url = '/create_pair/scope1/'
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.get('/get_keys/scope1/auser')
        self.assertEquals(rv.status_code, 200)
        self.assertIn('auser', rv.data)
        self.assertIn('ssh-rsa', rv.data)
        rv = self.app.get('/get_keys/bogus/auser')
        self.assertEquals(rv.status_code, 404)
        rv = self.app.get('/get_keys/scope3/auser')
        self.assertEquals(rv.status_code, 200)
        self.assertEquals('', rv.data)

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

    def test_get_keys(self):
        rv = self.app.get('/get_keys/auser')
        self.assertEquals(rv.status_code, 200)
        rv = self.app.get('/get_keys/buser')
        self.assertEquals(rv.status_code, 200)

    def test_reset(self):
        rv = self.app.delete('/reset', headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.delete('/reset', headers=self.badheaders)
        self.assertEquals(rv.status_code, 401)
        rv = self.app.delete('/reset', headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)

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
