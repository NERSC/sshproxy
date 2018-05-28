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


class APITestCase(unittest.TestCase):

    def setUp(self):
        os.environ['FAKEAUTH'] = '1'
        test_dir = os.path.dirname(os.path.abspath(__file__)) + "/../test/"
        self.test_dir = test_dir
        #os.environ['CONFIG'] = test_dir + '/config.yaml'
        import api
        self.app = api.app.test_client()
        self.headers = {'Authorization': 'Basic auser:password'}
        self.badheaders = {'Authorization': 'Basic auser:bad'}
        self.badmethod = {'Authorization': 'Blah auser:bad'}

    def get_all(self):
        r = []
        for rec in self.registry.find():
            r.append(rec)
        return r

    def get_pub(self, user, scope):
        r = self.registry.find_one({'user': user, 'scope': scope})
        return r['pubkey']

    def test_create_pair(self):
        rv = self.app.post('/create_pair', headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.post('/create_pair', headers=self.badheaders)
        self.assertEquals(rv.status_code, 403)
        rv = self.app.post('/create_pair', headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)
        # Missing auth
        rv = self.app.post('/create_pair')
        self.assertEquals(rv.status_code, 403)

    def test_pam(self):
        del os.environ['FAKEAUTH']
        rv = self.app.post('/create_pair', headers=self.headers)
        self.assertEquals(rv.status_code, 403)
        os.environ['FAKEAUTH'] = '1'

    def test_create_pai_scope(self):
        data = '{"skey": "scope1-secret"}'
        url = '/create_pair/scope1/'
        rv = self.app.post(url, data=data, headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.post(url, data=data, headers=self.badheaders)
        self.assertEquals(rv.status_code, 403)
        rv = self.app.post(url, data=data, headers=self.badmethod)
        self.assertEquals(rv.status_code, 403)
        # No data
        rv = self.app.post(url, headers=self.headers)
        self.assertEquals(rv.status_code, 403)
        # No skey
        rv = self.app.post(url, data='{"a": "b"}', headers=self.headers)
        self.assertEquals(rv.status_code, 403)

    def test_get_keys(self):
        rv = self.app.get('/get_keys/auser')
        self.assertEquals(rv.status_code, 200)
        rv = self.app.get('/get_keys/buser')
        self.assertEquals(rv.status_code, 200)

    def test_reset(self):
        rv = self.app.delete('/reset', headers=self.headers)
        self.assertEquals(rv.status_code, 200)
        rv = self.app.delete('/reset', headers=self.badheaders)
        self.assertEquals(rv.status_code, 403)
        rv = self.app.delete('/reset', headers=self.badmethod)
        self.assertEquals(rv.status_code, 401)



if __name__ == '__main__':
    unittest.main()
