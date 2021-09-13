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

import pytest
import os
import shutil
import sys

TEST_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT_DIR = os.path.join(os.path.dirname(TEST_ROOT_DIR), 'src')

sys.path.append(SRC_ROOT_DIR)
import nginx_config_helper

DATA_DIR = os.path.join(TEST_ROOT_DIR, 'data')

SITES_CONF_PREFIX = 'www.example.site'
SITES_CONF_AUTH_REQ_DIRECT_ARG = 'auth_req_direct_arg'
SITES_CONF_AUTH_REQ_INDIRECT_ARG = 'auth_req_indirect_arg'
SITES_CONF_NO_AUTH_REQ = 'no_auth_req'
NGINX_CONF_SINGLE_FILE = 'nginx.conf-single_file'
NGINX_CONF_USE_INCLUDES = 'nginx.conf-includes'
NGINX_CONF_INCORRECT = 'nginx.conf-incorrect'

SITES_ENABLED_DIR_PLACEHOLDER = '{sites_enabled_dir}'
DEFAULT_AUTH_REQUEST_PORT = 9444


# Copy test-specific nginx config files to a tmp directory
def _generate_nginx_conf(output_dir, site_test_case, nginx_conf_fname):
  output_nginx_conf = output_dir / "nginx.conf"
  nginx_conf_fname = os.path.join(DATA_DIR, nginx_conf_fname)
  with open(nginx_conf_fname, 'r') as nginx_conf_tmp:
    content = nginx_conf_tmp.read().replace(SITES_ENABLED_DIR_PLACEHOLDER,
                                            str(output_dir))
    output_nginx_conf.write_text(content)

  if site_test_case:
    site_fname = f'{SITES_CONF_PREFIX}-{site_test_case}'
    shutil.copyfile(os.path.join(DATA_DIR, site_fname),
                    os.path.join(str(output_dir), site_fname))
  return str(output_nginx_conf)


# Following tests use pytest's tmp_path fixture


@pytest.mark.parametrize(
    "nginx_n_site_test_cases,auth_req_is_valid",
    [((NGINX_CONF_SINGLE_FILE, None), True),
     ((NGINX_CONF_USE_INCLUDES, SITES_CONF_AUTH_REQ_DIRECT_ARG), True),
     ((NGINX_CONF_USE_INCLUDES, SITES_CONF_AUTH_REQ_INDIRECT_ARG), True),
     ((NGINX_CONF_USE_INCLUDES, SITES_CONF_NO_AUTH_REQ), False)])
def test_nginx_conf_variants(tmp_path, nginx_n_site_test_cases,
                             auth_req_is_valid):
  nginx_conf_in_fname, site_test_case = nginx_n_site_test_cases
  gen_nginx_conf_path = _generate_nginx_conf(
      tmp_path,
      site_test_case=site_test_case,
      nginx_conf_fname=nginx_conf_in_fname)
  helper = nginx_config_helper.ConfigHelper(
      gen_nginx_conf_path, auth_request_port=DEFAULT_AUTH_REQUEST_PORT)
  assert helper.has_auth_request() == auth_req_is_valid


@pytest.mark.parametrize("port,auth_req_is_valid",
                         [(DEFAULT_AUTH_REQUEST_PORT, True),
                          (DEFAULT_AUTH_REQUEST_PORT + 1, False)])
def test_auth_request_port_match(tmp_path, port, auth_req_is_valid):
  gen_nginx_conf_path = _generate_nginx_conf(
      tmp_path, site_test_case=None, nginx_conf_fname=NGINX_CONF_SINGLE_FILE)
  helper = nginx_config_helper.ConfigHelper(gen_nginx_conf_path,
                                            auth_request_port=port)
  assert helper.has_auth_request() == auth_req_is_valid


# If the nginx.conf is incorrectly formatted, then has_auth_request returns False
def test_nginx_conf_incorrect(tmp_path):
  gen_nginx_conf_path = _generate_nginx_conf(
      tmp_path,
      site_test_case=SITES_CONF_AUTH_REQ_DIRECT_ARG,
      nginx_conf_fname=NGINX_CONF_INCORRECT)
  helper = nginx_config_helper.ConfigHelper(
      gen_nginx_conf_path, auth_request_port=DEFAULT_AUTH_REQUEST_PORT)
  assert not helper.has_auth_request()
