#!/usr/bin/env python

# git clone https://github.com/authlib/example-oauth2-server.git
# cd example-oauth2-server
# flask initdb
# flask run

import requests

OAUTH_SERVER = 'http://localhost:5000'

session = requests.session()
r = session.post(OAUTH_SERVER, data=dict(
    username='test', email='test@example.org'))
r.raise_for_status()

r = session.post(OAUTH_SERVER + '/api/create_test_client', json=dict(
    redirect_uri='http://localhost:4080/oauth/callback/test',
    client_id='CLIENT_ID',
    client_secret='CLIENT_SECRET',
))
r.raise_for_status()
