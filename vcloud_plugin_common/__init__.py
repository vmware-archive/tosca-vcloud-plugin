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
from cloudify import context
from cloudify import exceptions as cfy_exc

TASK_RECHECK_TIMEOUT = 2
TASK_STATUS_SUCCESS = 'success'
TASK_STATUS_ERROR = 'error'

STATUS_COULD_NOT_BE_CREATED = -1
STATUS_UNRESOLVED = 0
STATUS_RESOLVED = 1
STATUS_DEPLOYED = 2
STATUS_SUSPENDED = 3
STATUS_POWERED_ON = 4
STATUS_POWERED_OFF = 8
STATUS_WAITING_FOR_USER_INPUT = 5
STATUS_UNKNOWN_STATE = 6
STATUS_UNRECOGNIZED_STATE = 7
STATUS_INCONSISTENT_STATE = 9

VCLOUD_STATUS_MAP = {
    -1 : "Could not be created",
    0 : "Unresolved",
    1 : "Resolved",
    2 : "Deployed",
    3 : "Suspended",
    4 : "Powered on",
    5 : "Waiting for user input",
    6 : "Unknown state",
    7 : "Unrecognized state",
    8 : "Powered off",
    9 : "Inconsistent state",
    10 : "Children do not all have the same status",
    11 : "Upload initiated, OVF descriptor pending",
    12 : "Upload initiated, copying contents",
    13 : "Upload initiated , disk contents pending",
    14 : "Upload has been quarantined",
    15 : "Upload quarantine period has expired"
    }


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


class VcloudAirClient(object):

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

        vcloud_air = self._login_and_get_vca(
            url, username, password, token, service, vdc)
        return vcloud_air

    def _login_and_get_vca(self, url, username, password, token, service, vdc):
        login_failed = False
        vdc_login_failed = False

        vca = vcloudair.VCA(
            url, username, service_type='subscription', version='5.6')
        if token:
            for _ in range(self.LOGIN_RETRY_NUM):
                success = vca.login(token=token)
                if success is False:
                    login_failed = True
                    ctx.logger.info("Login using token failed.")
                    continue
                else:
                    ctx.logger.info("Login using token successful.")
                    break

        if login_failed and password:
            login_failed = False
            for _ in range(self.LOGIN_RETRY_NUM):
                success = vca.login(password)
                if success is False:
                    login_failed = True
                    ctx.logger.info("Login using password failed. Retrying...")
                    continue
                else:
                    ctx.logger.info("Login using password successful.")
                    break

        for _ in range(self.LOGIN_RETRY_NUM):
            success = vca.login_to_org(service, vdc)
            if success is False:
                vdc_login_failed = True
                ctx.logger.info("Login to VDC failed. Retrying...")
                continue
            else:
                ctx.logger.info("Login to VDC successful.")
                break

        if login_failed:
            raise cfy_exc.NonRecoverableError("Invalid login credentials")
        if vdc_login_failed:
            raise cfy_exc.NonRecoverableError("Could not login to VDC")
    
        atexit.register(vca.logout)
        return vca


def with_vca_client(f):
    @wraps(f)
    def wrapper(*args, **kw):
        config = None
        if ctx.type == context.NODE_INSTANCE:
            config = ctx.node.properties.get('vcloud_config')
        elif ctx.type == context.RELATIONSHIP_INSTANCE:
            config = ctx.source.node.properties.get('vcloud_config')
        else:
            raise cfy_exc.NonRecoverableError("Unsupported context")
        client = VcloudAirClient().get(config=config)
        kw['vca_client'] = client
        return f(*args, **kw)
    return wrapper


def wait_for_task(vca_client, task):
    status = task.get_status()
    while status != TASK_STATUS_SUCCESS:
        if status == TASK_STATUS_ERROR:
            error = task.get_Error()
            raise cfy_exc.NonRecoverableError(
                "Error during task execution: {0}".format(error.get_message()))
        else:
            time.sleep(TASK_RECHECK_TIMEOUT)
            response = requests.get(
                task.get_href(),
                headers=vca_client.vcloud_session.get_vcloud_headers())
            task = taskType.parseString(response.content, True)
            status = task.get_status()


def get_vcloud_config():
    config = None
    if ctx.type == context.NODE_INSTANCE:
        config = ctx.node.properties.get('vcloud_config')
    elif ctx.type == context.RELATIONSHIP_INSTANCE:
        config = ctx.source.node.properties.get('vcloud_config')
    else:
        raise cfy_exc.NonRecoverableError("Unsupported context")
    static_config = Config().get()
    if config:
        static_config.update(config)
    return static_config
