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

import argparse
import json
import os
import signal
import sys
import subprocess
import time

AUTH_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(AUTH_ROOT_DIR, 'src')

sys.path.append(SRC_DIR)
import nginx_config_helper

ACCEPTED_USERS_ARG = '--accepted-users'
CUTTLEFISH_AUTH_DIR = 'android-cuttlefish-authentication'
LAUNCH_CVD_NAME = 'launch_cvd'
DEFAULT_NGINX_CONFIG_PATH = '/etc/nginx/nginx.conf'

DEFAULT_LAUNCH_CVD_FLAGS = ['--report_anonymous_usage_stats=n']
OVERRIDDEN_LAUNCH_CVD_FLAGS = [
    '--start_webrtc=true', '--webrtc_sig_server_secure=false'
]


def _print_err_exit(msg):
  print(msg, file=sys.stderr)
  fname = os.path.basename(os.path.realpath(__file__))
  print(f'usage: {fname} {ACCEPTED_USERS_ARG}=[emails] [launch_cvd args]',
        file=sys.stderr)
  exit(1)


def _run_until_SIG(*processes):
  def _clean_up_children(signum, stack):
    for proc in processes:
      if not proc.poll():
        proc.terminate()

  TERM_SIGS = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGCHLD]
  for sig in TERM_SIGS:
    signal.signal(sig, _clean_up_children)

  # wait until signals
  term_sig = signal.sigwait(TERM_SIGS)

  # SIGCHLD does not pass through the handler as other SIGs do.
  if term_sig == signal.SIGCHLD:
    _clean_up_children(signal.SIGCHLD, None)
  print(f'\nTerminated due to {term_sig}')


if __name__ == '__main__':
  parser = argparse.ArgumentParser(add_help=False)
  parser.add_argument(ACCEPTED_USERS_ARG,
                      nargs=1,
                      metavar='email',
                      help='Specify accepted user emails')
  parser.add_argument('--auth-request-port',
                      nargs='?',
                      default=9444,
                      metavar='port',
                      help='Specify the port for the auth_request server')
  args, unparsed_args = parser.parse_known_args()

  auth_root_parent, auth_root_dir_name = os.path.split(AUTH_ROOT_DIR)
  if os.getcwd() != auth_root_parent:
    _print_err_exit(
        'Script must be executed in the parent directory containing '
        f'the {auth_root_dir_name} directory')

  launch_cvd_file = os.path.join('bin', LAUNCH_CVD_NAME)
  if not os.path.exists(launch_cvd_file):
    launch_cvd_file = LAUNCH_CVD_NAME
    if not os.path.exists(launch_cvd_file):
      _print_err_exit(f'Cannot find {LAUNCH_CVD_NAME}')

  if not args.accepted_users:
    _print_err_exit(f'Cannot parse {ACCEPTED_USERS_ARG}')

  accepted_users = args.accepted_users[0].split(',')
  if len(accepted_users) < 1:
    _print_err_exit('Need to provide at least one user')

  if not os.path.exists(DEFAULT_NGINX_CONFIG_PATH):
    _print_err_exit('Must have nginx installed')

  # Determine if nginx has the required 'auth_request' directive
  config_helper = nginx_config_helper.ConfigHelper(
      DEFAULT_NGINX_CONFIG_PATH, auth_request_port=args.auth_request_port)
  if not config_helper.has_auth_request():
    _print_err_exit('Must specify auth_request directive in your nginx config')

  # Pass along rest of the args to launch_cvd
  # Initialize flags that can be overriden by users
  new_args = DEFAULT_LAUNCH_CVD_FLAGS

  # Add args that weren't used by this script
  new_args += unparsed_args

  # Since gflags, used by launch_cvd, will only consider the latest
  # --flag=value pairs in the command line, we can simply add our override flags
  # to the end.
  new_args += OVERRIDDEN_LAUNCH_CVD_FLAGS

  auth_request_server_cmd = [
      'python',
      os.path.join(SRC_DIR, 'auth_request_server.py'),
      f'--accepted-users={args.accepted_users[0]}', f'{args.auth_request_port}'
  ]

  _run_until_SIG(subprocess.Popen([launch_cvd_file] + new_args),
                 subprocess.Popen(auth_request_server_cmd))
