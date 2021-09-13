# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import flask
from flask import Flask, request, make_response

import google_auth_oauthlib.flow
import google.oauth2.credentials
from googleapiclient.discovery import build

import argparse
from datetime import datetime, timedelta
import hashlib
import jwt
import os
import sys
import threading
import time
import traceback

# This server
#  1) Acts as the authentication authority as per nginx's auth_request directive
#  2) Handles URL endpoints for starting and completing Google's Oauth2 flow

CLIENT_SECRETS_FILE = './secret.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 'openid']

# Note that for the sake of example, we use the client_secret.json (as provided
# by Google Cloud Console) to build our jwt secret. The jwt secret is used to
# encode and decode the jwt header.
JWT_SECRET = hashlib.sha512(
    open(CLIENT_SECRETS_FILE, 'r').read().encode('utf-8')).hexdigest(
    ) if os.path.exists(CLIENT_SECRETS_FILE) else 'INVALID_JWT_SECRET'

JWT_ALGORITHM = 'HS256'
JWT_EXP_TDELTA = timedelta(days=30)

# auth validation responses
NO_USER = 'no-user'
UNAUTHORIZED_USER = 'unauthed-user'
AUTHORIZED_USER = 'user'
TOKEN_EXPIRED = 'token-expired'

# Cookie key for the access token.
ACCESS_TOKEN = 'atoken'

# Cookie key for session related data.
SESSION = 'session'

# Session key for storing the user-intended url. Using this info, we can
# redirect the user to the intended url after they successfully logged in.
ORIGINAL_URL_KEY = 'original_url'

# Session key for passing user's ID (e.g. email) after user has logged in
# (or failed to log in).
USER_KEY = 'user'

# Setting this in the shell environment allows us to bypass TLS requirement for
# Google Oauth.  This is meant for development purposes.
OAUTH_ENV_KEY = 'OAUTHLIB_INSECURE_TRANSPORT'


def _jwt_encode(payload):
  return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)


def _jwt_decode(token):
  return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def _get_session_cookie(request):
  return request.cookies[SESSION] if SESSION in request.cookies else None


def _get_session_value(request, key):
  if SESSION in request.cookies:
    session_data = _jwt_decode(request.cookies[SESSION])
    if key in session_data:
      return session_data[key]
  return None


def _set_session_value(response, key, value, session_encoded=None):
  session_data = _jwt_decode(session_encoded) if session_encoded else {}
  session_data[key] = value
  response.set_cookie(SESSION, _jwt_encode(session_data))


def _respond_with_session_value(response, key, value, session_encoded=None):
  _set_session_value(response, key, value, session_encoded=None)
  return response


def _decode_atoken(token, valid_users=[]):
  try:
    payload = _jwt_decode(token)
    if 'exp' in payload and datetime.fromtimestamp(
        payload['exp']) < datetime.now():
      return TOKEN_EXPIRED
    if 'user' in payload and payload['user'] in valid_users:
      return AUTHORIZED_USER
  except jwt.exceptions.ExpiredSignatureError:
    return TOKEN_EXPIRED
  except:
    traceback.print_exc()
    print("Unexpected error:", sys.exc_info()[0])
  return UNAUTHORIZED_USER


def _validate_request(request, valid_users=[]):
  token = None
  if 'Authorization' in request.headers:
    token = request.headers['Authorization'].split(' ')[1]
  if ACCESS_TOKEN in request.cookies:
    token = request.cookies[ACCESS_TOKEN]
  if token is None:
    return NO_USER
  return _decode_atoken(token, valid_users)


# We cache tokens so that the one token is provided for one user for an alotted
# time. Note that this implementation is written for the sake of simplicity. It
# lacks token refresh and session/device isolation.
def _generate_atoken(email, token_store):
  if email in token_store:
    return token_store[email]

  now = datetime.now()
  payload = {
      'user': email,
      'issued': datetime.timestamp(now),
      'exp': datetime.timestamp(now + JWT_EXP_TDELTA)
  }
  token = _jwt_encode(payload)
  token_store[email] = token
  return token


def _modify_scheme(orig_uri):
  if OAUTH_ENV_KEY not in os.environ or os.environ[OAUTH_ENV_KEY] != '1':
    orig_uri = orig_uri.replace('http://', 'https://')
  return orig_uri


def _get_redirect_uri():
  redirect_uri = flask.url_for('oauth2callback', _external=True)
  return _modify_scheme(redirect_uri)


class OauthProvider:
  def __init__(self, state=None):
    self.flow_ = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    self.flow_.redirect_uri = _get_redirect_uri()

  def get_auth_url(self):
    authorization_url, state = self.flow_.authorization_url(
        access_type='offline', include_granted_scopes='true')
    return authorization_url

  def get_credentials(self, response_url):
    # Fetch a token to access Google APIs
    self.flow_.fetch_token(authorization_response=response_url)

    return self.flow_.credentials


class UserEmailRetriever:
  def __init__(self, credentials):
    self.credentials_ = credentials

  def get_email(self):
    user_info_service = build(serviceName='oauth2',
                              version='v2',
                              credentials=self.credentials_)
    user_info = None
    try:
      user_info = user_info_service.userinfo().get().execute()
    except e:
      logging.error('An error occurred: %s', e)
    return user_info['email'] if user_info else None


def create_app(accepted_users, token_store):
  def clean_token_store():
    remove = [email for email, token in token_store.items() \
      if _decode_atoken(token, accepted_users) != AUTHORIZED_USER]
    for r in remove:
      token_store.pop(r, None)

  app = Flask(__name__)

  # Start the flow for authorizing a user. This will go through Google's Oauth2
  # flow.
  @app.route('/login/')
  def login():
    return _respond_with_session_value(
        flask.redirect(OauthProvider().get_auth_url()), ORIGINAL_URL_KEY,
        request.args.get('url'), _get_session_cookie(request))

  # User will be redirected here after Google's auth flow completes.
  @app.route('/oauth2callback/')
  def oauth2callback():
    session_cookie = _get_session_cookie(request)
    state = request.args.get('state')

    credentials = OauthProvider(state=state).get_credentials(
        response_url=_modify_scheme(flask.request.url))

    email = UserEmailRetriever(credentials=credentials).get_email()
    if not email:
      return _respond_with_session_value(
          flask.redirect(flask.url_for('unauthorized')), USER_KEY,
          'Unknown User', session_cookie)

    # Check if the email we've retrived is among the ones provided when starting
    # this server. If it is, we redirect the user to where they originally
    # wanted to go.
    if email not in accepted_users:
      return _respond_with_session_value(
          flask.redirect(flask.url_for('unauthorized')), USER_KEY, email,
          session_cookie)

    original_url = _get_session_value(request, ORIGINAL_URL_KEY)
    resp = flask.redirect(original_url if original_url else '/')
    _set_session_value(resp, USER_KEY, email, session_cookie)

    clean_token_store()
    resp.set_cookie(ACCESS_TOKEN, _generate_atoken(email, token_store))
    return resp

  @app.route('/validate-auth')
  def validate_auth():
    res = _validate_request(request, valid_users=accepted_users)
    if res != AUTHORIZED_USER:
      response = make_response('', 401)
      response.headers['x-authreq-err'] = res
      return response
    return '', 200

  @app.route('/unauthorized/')
  def unauthorized():
    user = _get_session_value(request, USER_KEY)
    if user is None:
      user = 'User'
    return f'{user} is not authorized for this app'

  app.url_map.strict_slashes = False

  return app


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('port',
                      metavar='port',
                      type=int,
                      nargs=1,
                      help='port to run the server on')
  parser.add_argument('--dev', action="store_true", help='Run dev version')
  parser.add_argument('--accepted-users',
                      type=str,
                      help='comma-separated list of accepted users')
  args, _ = parser.parse_known_args(sys.argv[1:])

  token_store = {}
  accepted_users = []

  if args.accepted_users:
    accepted_users = args.accepted_users.split(',')

  if args.dev:
    # For local development only. This allows for redirection to urls without
    # TLS.
    os.environ[OAUTH_ENV_KEY] = '1'
    print('running dev version')

  app = create_app(accepted_users, token_store)

  # This will run on current thread. We keep it out of create_app so that tests
  # can be written.
  app.run(host='127.0.0.1', port=args.port[0])


if __name__ == '__main__':
  main()
