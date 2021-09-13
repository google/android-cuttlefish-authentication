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

import crossplane
import sys


class ConfigElement:
  def __init__(self, config_struct):
    self._directive = config_struct[
        'directive'] if 'directive' in config_struct else None
    self._args = config_struct['args'] if 'args' in config_struct else []
    self._block = config_struct['block'] if 'block' in config_struct else []
    self._includes = config_struct[
        'includes'] if 'includes' in config_struct else []
    if 'parsed' in config_struct:
      self._block = config_struct['parsed']
    self._children = [ConfigElement(b) for b in self._block]

  def find_children(self, child_dir):
    return filter(lambda c: c.dir() == child_dir, self._children)

  def dir(self):
    return self._directive

  def args(self):
    return self._args

  def includes(self):
    return self._includes

  def has_arg(self, arg):
    return arg in self._args

  def loose_arg_match(self, arg):
    for sarg in self._args:
      if arg in sarg:
        return True
    return False

  def block(self):
    return self._block


class ConfigHelper:
  def __init__(self, config_path, auth_request_port=-1):
    self._servers = []
    self._auth_request_port = auth_request_port

    if crossplane.parse(config_path)['status'] != 'ok':
      print(f'Failed to parse {config_path}', file=sys.stderr)
      return

    payload = crossplane.parse(config_path)['config']

    # Find all the http contexts
    https = []
    for file_block in payload:
      https += list(ConfigElement(file_block).find_children('http'))

    includes_in_https = []
    for http in https:
      # Find any server block defined in the http context
      self._servers += list(http.find_children('server'))

      # Track files that are included in the http context
      for inc in http.find_children('include'):
        includes_in_https += inc.includes()

    # For files included in a http context, check if there are server blocks
    for file_block in [
        payload[file_ind] for file_ind in set(includes_in_https)
    ]:
      self._servers += list(ConfigElement(file_block).find_children('server'))

  def has_auth_request(self):
    auth_req_parents = []
    all_locations = []
    for server in self._servers:
      auth_req_parents += list(server.find_children('auth_request'))
      all_locations += list(server.find_children('location'))

    for location in all_locations:
      auth_req_parents += list(location.find_children('auth_request'))

    for auth_req in auth_req_parents:
      # Try to see if the given port can be found in the auth_request line
      if auth_req.loose_arg_match(f':{self._auth_request_port}'):
        return True

      # Else, try matching a location to the auth_request url and see if the
      # port matches
      for url in auth_req.args():
        for location in all_locations:
          if not location.loose_arg_match(url):
            continue
          for proxy_pass in location.find_children('proxy_pass'):
            if proxy_pass.loose_arg_match(f':{self._auth_request_port}'):
              return True
    return False
