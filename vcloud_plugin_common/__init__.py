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
import requests
import time

from pyvcloud import vcloudair
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType

from cloudify import ctx
from cloudify import exceptions as cfy_exc

TASK_RECHECK_TIMEOUT = 2
TASK_STATUS_SUCCESS = 'success'
TASK_STATUS_ERROR = 'error'


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
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config.json'

    def get(self):
        cfg = {}
        env_name = self.VCLOUD_CONFIG_PATH_ENV_VAR
        default_location_tpl = self.VCLOUD_CONFIG_PATH_DEFAULT
        default_location = os.path.expanduser(default_location_tpl)
        config_path = os.getenv(env_name, default_location)
        try:
            with open(config_path) as f:
                cfg = json.loads(f.read())
        except IOError:
            pass
        return cfg


class VcloudDirectorClient(object):

    config = Config
    LOGIN_RETRY_NUM = 5

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
        service = cfg.get('service')
        vdc = cfg.get('vdc')
        if not (all([url, token]) or all([url, username, password])):
            raise cfy_exc.NonRecoverableError(
                "Login credentials must be specified")
        if not (service and vdc):
            raise cfy_exc.NonRecoverableError(
                "vCloud service and vDC must be specified")

        vcloud_director = self.login_and_get_vcd(
            self, url, username, password, token, service, vdc)
        if vcloud_director is None:
            raise cfy_exc.NonRecoverableError(
                "Could not get vCloud Director reference")
        else:
            return vcloud_director

    def _login_and_get_vcd(self, url, username, password, token, service, vdc):
        vcd = None
        login_failed = False
        for _ in range(self.LOGIN_RETRY_NUM):
            vca = vcloudair.VCA()
            success = vca.login(url, username, password, token)
            if success is False:
                login_failed = True
                continue
            else:
                atexit.register(vca.logout)
            vcd = vca.get_vCloudDirector(service, vdc)
            if vcd is None:
                continue
        if login_failed:
            raise cfy_exc.NonRecoverableError("Invalid login credentials")
        return vcd


def with_vcd_client(f):
    @wraps(f)
    def wrapper(*args, **kw):
        config = ctx.node.properties.get('vcloud_config')
        client = VcloudDirectorClient().get(config=config)
        kw['vcd_client'] = client
        return f(*args, **kw)
    return wrapper


def wait_for_task(vcd_client, task):
    status = task.get_status()
    while status != TASK_STATUS_SUCCESS:
        if status == TASK_STATUS_ERROR:
            error = task.get_Error()
            raise cfy_exc.NonRecoverableError(
                "Error during task execution: {0}".format(error.get_message()))
        else:
            time.sleep(TASK_RECHECK_TIMEOUT)
            response = requests.get(task.get_href(),
                                    headers=vcd_client.headers)
            task = taskType.parseString(response.content, True)
            status = task.get_status()
