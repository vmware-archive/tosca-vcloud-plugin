# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import atexit
from functools import wraps
import json
import os

from pyvcloud import vcloudair

from cloudify import ctx


def transform_resource_name(res, ctx):

    if isinstance(res, basestring):
        res = {'name': res}

    if not isinstance(res, dict):
        raise ValueError("transform_resource_name() expects either string or "
                         "dict as the first parameter")

    pfx = ctx.bootstrap_context.resources_prefix

    if not pfx:
        return res['name']

    name = res['name']
    res['name'] = pfx + name

    if name.startswith(pfx):
        ctx.logger.warn("Prefixing resource '{0}' with '{1}' but it "
                        "already has this prefix".format(name, pfx))
    else:
        ctx.logger.info("Transformed resource name '{0}' to '{1}'".format(
                        name, res['name']))

    return res['name']


class Config(object):

    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT_PATH = '~/vcloud_config.json'

    def get(self):
        cfg = {}
        env_name = self.VCLOUD_CONFIG_PATH_ENV_VAR
        default_location_tpl = self.VCLOUD_CONFIG_PATH_DEFAULT_PATH
        default_location = os.path.expanduser(default_location_tpl)
        config_path = os.getenv(env_name, default_location)
        try:
            with open(config_path) as f:
                cfg = json.loads(f.read())
        except IOError:
            pass
        return cfg


class VcloudClient(object):

    config = Config

    def get(self, config=None, *args, **kw):
        static_config = self.__class__.config().get()
        cfg = {}
        cfg.update(static_config)
        if config:
            cfg.update(config)
        return self.connect(cfg)

    def connect(self, cfg):
        url = cfg.get('url')
        username = cfg.get('username')
        password = cfg.get('password')
        token = cfg.get('token')
        if not(all([url, token]) or all([url, username, password])):
            raise cfy_exc.NonRecoverableError(
                "Login credentials must be specified")

        client = vcloudair.VCA()
        success = client.login(url, username, password, token)
        if success is False:
            raise cfy_exc.NonRecoverableError("Invalid login credentials")
        else:
            atexit.register(client.logout())
            return client


def with_vcloud_client(f):
    @wraps(f)
    def wrapper(*args, **kw):
        config = ctx.node.properties.get('vcloud_config')
        client = VcloudClient().get(config=config)
        kw['vcloud_client'] = client
        return f(*args, **kw)
    return wrapper
