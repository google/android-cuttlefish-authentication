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

from datetime import timedelta
import flask
import os
import pytest
import sys
import time

TEST_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT_DIR = os.path.join(os.path.dirname(TEST_ROOT_DIR), 'src')

sys.path.append(SRC_ROOT_DIR)
import auth_request_server
from auth_request_server import create_app, USER_KEY, ACCESS_TOKEN,\
  SESSION,_generate_atoken,_jwt_decode

MOCK_AUTH_URL = 'https://www.example.site/auth'
MOCK_OAUTH_CREDENTIALS = {}
MOCK_EMAIL_1 = 'user1@example.site'
MOCK_EMAIL_2 = 'user2@example.site'
MOCK_ACCEPTED_USERS = [MOCK_EMAIL_1, MOCK_EMAIL_2]

TEST_JWT_SECRET = 'test_jwt_secret'


@pytest.fixture
def mock_auth_classes(mocker):
  mocker.patch.object(auth_request_server, 'JWT_SECRET', TEST_JWT_SECRET)

  oauth_class = mocker.patch('auth_request_server.OauthProvider')
  oauth_provider = oauth_class.return_value
  oauth_provider.get_auth_url.return_value = MOCK_AUTH_URL
  oauth_provider.get_credentials.return_value = MOCK_OAUTH_CREDENTIALS

  email_retriever_class = mocker.patch(
      'auth_request_server.UserEmailRetriever')
  email_retriever = email_retriever_class.return_value
  email_retriever.get_email.return_value = MOCK_EMAIL_1
  return (oauth_provider, email_retriever)


def _get_user_from_cookie(client):
  session_cookie = next(
      (cookie for cookie in client.cookie_jar if cookie.name == SESSION), None)
  session = _jwt_decode(session_cookie.value)
  return session[USER_KEY] if USER_KEY in session else None


def test_endpoint_login(mock_auth_classes):
  with create_app([], {}).test_client() as client:
    rv = client.get('/login/')
    assert rv.location == MOCK_AUTH_URL


def test_endpoint_oauth2callback(mock_auth_classes):
  # Email is part of accepted list
  with create_app(MOCK_ACCEPTED_USERS, {}).test_client() as client:
    rv = client.get('/oauth2callback/')
    assert rv.status_code == 302
    assert rv.location.endswith('/localhost/')
    assert _get_user_from_cookie(client) == MOCK_EMAIL_1


def test_endpoint_oauth2callback_incorrect_email(mock_auth_classes):
  # Email is not part of accepted list
  with create_app([], {}).test_client() as client:
    rv = client.get('/oauth2callback/')
    assert rv.status_code == 302
    assert 'unauthorized' in rv.location
    assert _get_user_from_cookie(client) == MOCK_EMAIL_1


def test_endpoint_oauth2callback_email_retrieval_failed(mock_auth_classes):
  _, email_retriever = mock_auth_classes
  email_retriever.get_email.return_value = None

  with create_app(MOCK_ACCEPTED_USERS, {}).test_client() as client:
    rv = client.get('/oauth2callback/')
    assert rv.status_code == 302
    assert 'unauthorized' in rv.location
    # Email retriever failed so we did not retrieve a valid email for this user.
    assert _get_user_from_cookie(client) != MOCK_EMAIL_1


def test_endpoint_validate_auth(mocker, mock_auth_classes):
  app = create_app(MOCK_ACCEPTED_USERS, {})
  # Test with no token
  with app.test_client() as client:
    rv = client.get('/validate-auth')
    assert rv.status_code == 401

  # Use a separate test client to clear out cookies
  # Test with a valid token
  with app.test_client() as client:
    client.set_cookie(server_name='',
                      key=ACCESS_TOKEN,
                      value=_generate_atoken(MOCK_EMAIL_1, {}))
    rv = client.get('/validate-auth')
    assert rv.status_code == 200


def test_token_store_is_valid(mocker, mock_auth_classes):
  _, email_retriever = mock_auth_classes
  token_store = {}
  app = create_app(MOCK_ACCEPTED_USERS, token_store)

  with app.test_client() as client:
    # This request will create a token and store it in token_store
    # The following line is to make explicit that two different emails are used
    # to generate two different tokens.
    email_retriever.get_email.return_value = MOCK_EMAIL_1
    rv = client.get('/oauth2callback/')

    assert MOCK_EMAIL_1 in token_store

    email_1_token = token_store[MOCK_EMAIL_1]

    # Make another token by mocking a second user making the request.
    email_retriever.get_email.return_value = MOCK_EMAIL_2

    # Mock so that this token will already be expired by the moment it is
    # generated.
    mocker.patch.object(auth_request_server, 'JWT_EXP_TDELTA',
                        timedelta(seconds=0))
    rv = client.get('/oauth2callback/')

    assert len(token_store) == 2

    # token_store needs to be in a valid state when _generate_atoken is called,
    # which means the expired token should have been removed. We check this
    # condition by mocking out _generate_atoken.
    mocker.patch('auth_request_server._generate_atoken')
    auth_request_server._generate_atoken.return_value = email_1_token
    email_retriever.get_email.return_value = MOCK_EMAIL_1
    rv = client.get('/oauth2callback/')
    expected_store = {MOCK_EMAIL_1: email_1_token}
    auth_request_server._generate_atoken.assert_called_once_with(
        MOCK_EMAIL_1, expected_store)
