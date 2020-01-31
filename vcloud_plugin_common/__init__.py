# Copyright (c) 2014-2020 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import atexit
from functools import wraps
import yaml
import os
import requests
import time
import collections

from pyvcloud import vcloudair
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType
from cloudify.context import ImmutableProperties

from cloudify import ctx
from cloudify import context
from cloudify import exceptions as cfy_exc


TASK_RECHECK_TIMEOUT = 5
RELOGIN_TIMEOUT = 5
LOGIN_RETRY_NUM = 15
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
    -1: "Could not be created",
    0: "Unresolved",
    1: "Resolved",
    2: "Deployed",
    3: "Suspended",
    4: "Powered on",
    5: "Waiting for user input",
    6: "Unknown state",
    7: "Unrecognized state",
    8: "Powered off",
    9: "Inconsistent state",
    10: "Children do not all have the same status",
    11: "Upload initiated, OVF descriptor pending",
    12: "Upload initiated, copying contents",
    13: "Upload initiated , disk contents pending",
    14: "Upload has been quarantined",
    15: "Upload quarantine period has expired"
}

SUBSCRIPTION_SERVICE_TYPE = 'subscription'
ONDEMAND_SERVICE_TYPE = 'ondemand'
PRIVATE_SERVICE_TYPE = 'vcd'
SESSION_TOKEN = 'session_token'
ORG_URL = 'org_url'
VCLOUD_CONFIG = 'vcloud_config'

local_session_token = None
local_org_url = None


def transform_resource_name(res, ctx):
    """
        return name as prefix from bootstrap context + resource name
    """
    if isinstance(res, basestring):
        res = {'name': res}

    if not isinstance(res, dict):
        raise ValueError("transform_resource_name() expects either string or "
                         "dict as the first parameter")

    pfx = ctx.bootstrap_context.resources_prefix

    if not pfx:
        return get_mandatory(res, 'name')

    name = get_mandatory(res, 'name')
    res['name'] = pfx + name

    if name.startswith(pfx):
        ctx.logger.warn("Prefixing resource '{0}' with '{1}' but it "
                        "already has this prefix".format(name, pfx))
    else:
        ctx.logger.info("Transformed resource name '{0}' to '{1}'".format(
                        name, res['name']))

    return res['name']


class Config(object):
    """
        load global config
    """

    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config.yaml'

    def get(self):
        """
            return settings from ~/vcloud_config.yaml
        """
        cfg = {}
        env_name = self.VCLOUD_CONFIG_PATH_ENV_VAR
        default_location_tpl = self.VCLOUD_CONFIG_PATH_DEFAULT
        default_location = os.path.expanduser(default_location_tpl)
        config_path = os.getenv(env_name, default_location)
        try:
            with open(config_path) as f:
                cfg = yaml.load(f.read())
                if not cfg:
                    cfg = {}
        except IOError:
            pass
        return cfg


class VcloudAirClient(object):

    config = Config

    def get(self, config=None, *args, **kw):
        """
            return new vca client
        """
        static_config = self.__class__.config().get()
        cfg = {}
        cfg.update(static_config)
        if config:
            cfg.update(config)
        return self.connect(cfg)

    def connect(self, cfg):
        """
            login to instance described in settings
        """
        url = cfg.get('url')
        username = cfg.get('username')
        password = cfg.get('password')
        token = cfg.get('token')
        service = cfg.get('service')
        org_name = cfg.get('org')
        service_type = cfg.get('service_type', SUBSCRIPTION_SERVICE_TYPE)
        instance = cfg.get('instance')
        org_url = cfg.get(ORG_URL, None)
        verify = cfg.get('ssl_verify', True)
        api_version = cfg.get('api_version', '5.6')
        session_token = cfg.get(SESSION_TOKEN)
        org_url = cfg.get(ORG_URL)
        if not (all([url, token]) or
           all([url, username, password])
           or session_token):
            raise cfy_exc.NonRecoverableError(
                "Login credentials must be specified.")
        if (service_type == SUBSCRIPTION_SERVICE_TYPE and not (
            service and org_name
        )):
            raise cfy_exc.NonRecoverableError(
                "vCloud service and vDC must be specified")

        if service_type == SUBSCRIPTION_SERVICE_TYPE:
            vcloud_air = self._subscription_login(
                url, username, password, token, service, org_name,
                session_token, org_url)
        elif service_type == ONDEMAND_SERVICE_TYPE:
            vcloud_air = self._ondemand_login(
                url, username, password, token, instance,
                session_token, org_url)
        # The actual service type for private is 'vcd', but we should accept
        # 'private' as well, for user friendliness of inputs
        elif service_type in (PRIVATE_SERVICE_TYPE, 'private'):
            vcloud_air = self._private_login(
                url, username, password, token, org_name, org_url,
                api_version, verify)
        else:
            raise cfy_exc.NonRecoverableError(
                "Unrecognized service type: {0}".format(service_type))
        return vcloud_air

    def _subscription_login(self, url, username, password, token, service,
                            org_name, session_token=None, org_url=None):
        """
            login to subscription service
        """
        version = '5.6'
        logined = False
        vdc_logined = False
        vca = vcloudair.VCA(
            url, username, service_type=SUBSCRIPTION_SERVICE_TYPE,
            version=version)

        if session_token:
            vca = login_to_vca_with_token(vca, org_url, session_token, version)
            if vca:
                return vca
            else:
                raise cfy_exc.NonRecoverableError(
                    "Invalid session credentials")

        global local_org_url
        global local_session_token
        if local_session_token:
            vca = login_to_vca_with_token(vca, local_org_url,
                                          local_session_token, version)
            if vca:
                return vca

        # login with token
        if token:
            logined = login_with_retry(vca.login, [None, token],
                                       "Login using token")

        # outdated token, try login by password
        if logined is False and password:
            logined = login_with_retry(vca.login, [password, None],
                                       "Login using token")

        # can't login to system at all
        if logined is False:
            raise cfy_exc.NonRecoverableError("Invalid login credentials")

        vdc_logined = login_with_retry(vca.login_to_org, [service, org_name],
                                       "Login to org")

        # we can login to system,
        # but have some troubles with login to organization,
        # lets retry later
        if vdc_logined:
            local_session_token = vca.vcloud_session.token
            local_org_url = vca.vcloud_session.org_url
        else:
            raise cfy_exc.RecoverableError(message="Could not login to VDC",
                                           retry_after=RELOGIN_TIMEOUT)

        atexit.register(vca.logout)
        return vca

    def _ondemand_login(self, url, username, password, token, instance_id,
                        session_token=None, org_url=None):
        """
            login to ondemand service
        """
        def get_instance(vca, instance_id):
            instances = vca.get_instances() or []
            for instance in instances:
                if instance['id'] == instance_id:
                    return instance

        version = '5.7'
        if instance_id is None:
            raise cfy_exc.NonRecoverableError(
                "Instance ID should be specified for OnDemand login")
        logined = False
        instance_logined = False

        vca = vcloudair.VCA(
            url, username, service_type=ONDEMAND_SERVICE_TYPE, version=version)
        if session_token:
            vca = login_to_vca_with_token(vca, org_url, session_token, version)
            if vca:
                return vca
            else:
                raise cfy_exc.NonRecoverableError(
                    "Invalid session credentials")

        global local_org_url
        global local_session_token
        if local_session_token:
            vca = login_to_vca_with_token(vca, local_org_url,
                                          local_session_token, version)
            if vca:
                return vca

        # login with token
        if token:
            logined = login_with_retry(vca.login, [None, token],
                                       "Login using token")

        # outdated token, try login by password
        if logined is False and password:
            logined = login_with_retry(vca.login, [password, None],
                                       "Login using password")

        # can't login to system at all
        if logined is False:
            raise cfy_exc.NonRecoverableError("Invalid login credentials")

        instance = get_instance(vca, instance_id)
        if instance is None:
            raise cfy_exc.NonRecoverableError(
                "Instance {0} could not be found.".format(instance_id))

        instance_logined = login_with_retry(vca.login_to_instance,
                                            [instance_id, password],
                                            "Login to instance with password")

        if instance_logined:
            instance_logined = login_with_retry(vca.login_to_instance,
                                                [instance_id, None,
                                                 vca.vcloud_session.token,
                                                 vca.vcloud_session.org_url],
                                                "Login to instance with token")

        # we can login to system,
        # but have some troubles with login to instance,
        # lets retry later
        if instance_logined:
            local_session_token = vca.vcloud_session.token
            local_org_url = vca.vcloud_session.org_url
        else:
            raise cfy_exc.RecoverableError(
                message="Could not login to instance",
                retry_after=RELOGIN_TIMEOUT)

        atexit.register(vca.logout)
        return vca

    def _private_login(self, url, username, password, token, org_name,
                       org_url=None, api_version='5.6', verify=True):
        """
            login to private instance
        """
        logined = False

        vca = vcloudair.VCA(
            host=url,
            username=username,
            service_type=PRIVATE_SERVICE_TYPE,
            version=api_version,
            verify=verify)

        if logined is False and password:
            for _ in xrange(LOGIN_RETRY_NUM):
                logined = vca.login(password, org=org_name)
                if logined is False:
                    ctx.logger.info("Login using password failed. Retrying...")
                    time.sleep(RELOGIN_TIMEOUT)
                    continue
                else:
                    token = vca.token
                    # Set org_url based on the session, no matter what was
                    # passed in to the application, as this is guaranteed to
                    # be correct
                    org_url = vca.vcloud_session.org_url
                    ctx.logger.info("Login using password successful.")
                    break

        # Private mode requires being logged in with a token otherwise you
        # don't seem to be able to retrieve any VDCs
        if token:
            for _ in xrange(LOGIN_RETRY_NUM):
                logined = vca.login(token=token, org_url=org_url)
                if logined is False:
                    ctx.logger.info("Login using token failed.")
                    time.sleep(RELOGIN_TIMEOUT)
                    continue
                else:
                    ctx.logger.info("Login using token successful.")
                    break

        if logined is False:
            raise cfy_exc.NonRecoverableError("Invalid login credentials")

        atexit.register(vca.logout)
        return vca


def _update_nested(d, u):
    for k, v in u.iteritems():
        if isinstance(v, collections.Mapping):
            r = _update_nested(d.get(k, {}), v)
            d[k] = r
        else:
            d[k] = u[k]
    return d


def _update_static_properties(node, kw, element):
    if element in kw:
        node._node = node._endpoint.get_node(node.id)
        props = node._node.get('properties', {})
        _update_nested(props, kw[element])
        node._node['properties'] = ImmutableProperties(props)


def with_vca_client(f):
    """
        add vca client to function params
    """
    @wraps(f)
    def wrapper(*args, **kw):
        config = None
        prop = None
        if ctx.type == context.NODE_INSTANCE:
            _update_static_properties(ctx.node, kw, 'properties')
            config = ctx.node.properties.get(VCLOUD_CONFIG)
            prop = ctx.instance.runtime_properties
        elif ctx.type == context.RELATIONSHIP_INSTANCE:
            _update_static_properties(ctx.source.node, kw, 'source')
            _update_static_properties(ctx.target.node, kw, 'target')
            config = ctx.source.node.properties.get(VCLOUD_CONFIG)
            if config:
                prop = ctx.source.instance.runtime_properties
            else:
                config = ctx.target.node.properties.get(VCLOUD_CONFIG)
                prop = ctx.target.instance.runtime_properties
        else:
            raise cfy_exc.NonRecoverableError("Unsupported context")
        if config and prop:
            config[SESSION_TOKEN] = prop.get(SESSION_TOKEN)
            config[ORG_URL] = prop.get(ORG_URL)
        client = VcloudAirClient().get(config=config)
        kw['vca_client'] = client
        return f(*args, **kw)
    return wrapper


def wait_for_task(vca_client, task):
    """
        check status of current task and make request for recheck
        task status in case when we have not well defined state
        (not error and not success or by timeout)
    """
    WAIT_TIME_MAX_MINUTES = 30
    MAX_ATTEMPTS = WAIT_TIME_MAX_MINUTES * 60 / TASK_RECHECK_TIMEOUT
    ctx.logger.debug('Maximun task wait time {0} minutes.'
                     .format(WAIT_TIME_MAX_MINUTES))
    ctx.logger.debug('Task recheck after {0} seconds.'
                     .format(TASK_RECHECK_TIMEOUT))
    status = task.get_status()
    config = get_vcloud_config()
    for attempt in xrange(MAX_ATTEMPTS):
        ctx.logger.debug('Attempt: {0}/{1}.'.format(attempt + 1, MAX_ATTEMPTS))
        if status == TASK_STATUS_SUCCESS:
            ctx.logger.debug('Task completed in {0} seconds'
                             .format(attempt * TASK_RECHECK_TIMEOUT))
            return
        if status == TASK_STATUS_ERROR:
            error = task.get_Error()
            raise cfy_exc.NonRecoverableError(
                "Error during task execution: {0}".format(error.get_message()))
        time.sleep(TASK_RECHECK_TIMEOUT)
        response = requests.get(
            task.get_href(),
            headers=vca_client.vcloud_session.get_vcloud_headers(),
            verify=config.get('ssl_verify', True))
        task = taskType.parseString(response.content, True)
        status = task.get_status()
    raise cfy_exc.NonRecoverableError("Wait for task timeout.")


def get_vcloud_config():
    """
        get vcloud config from node properties
    """
    config = None
    if ctx.type == context.NODE_INSTANCE:
        config = ctx.node.properties.get(VCLOUD_CONFIG)
    elif ctx.type == context.RELATIONSHIP_INSTANCE:
        config = ctx.source.node.properties.get(VCLOUD_CONFIG)
        if not config:
            config = ctx.target.node.properties.get(VCLOUD_CONFIG)
    else:
        raise cfy_exc.NonRecoverableError("Unsupported context")
    static_config = Config().get()
    if config:
        static_config.update(config)
    return static_config


def get_mandatory(obj, parameter):
    """
        return value for field or raise exception if field does not exist
    """
    value = obj.get(parameter)
    if value:
        return value
    else:
        raise cfy_exc.NonRecoverableError(
            "Mandatory parameter {0} is absent".format(parameter))


def is_subscription(service_type):
    """
        check service type is subscription or empty
    """
    return not service_type or service_type == SUBSCRIPTION_SERVICE_TYPE


def is_ondemand(service_type):
    """
        check service type is ondemand
    """
    return service_type == ONDEMAND_SERVICE_TYPE


def error_response(obj):
    """
        return description of response error
    """
    try:
        return obj.response.content
    except AttributeError:
        return ''


def session_login(vca, org_url, session_token, version):
    vcs = vcloudair.VCS(org_url, None, None, None, org_url, org_url, version)
    for _ in xrange(LOGIN_RETRY_NUM):
        if not vcs.login(token=session_token):
            ctx.logger.info("Login using session token failed.")
            time.sleep(RELOGIN_TIMEOUT)
            continue
        else:
            vca.vcloud_session = vcs
            ctx.logger.info("Login using session token successful.")
            return True
    return False


def login_to_vca_with_token(vca, org_url, session_token, version):
    for _ in xrange(LOGIN_RETRY_NUM):
        logined = session_login(vca, org_url, session_token, version)
        if logined is False:
            ctx.logger.info("Login using session token failed.")
            time.sleep(RELOGIN_TIMEOUT)
            continue
        else:
            return vca


def login_with_retry(function, arguments, message):
    for _ in xrange(LOGIN_RETRY_NUM):
        logined = function(*arguments)
        if logined is False:
            ctx.logger.info("{0} failed. Retrying...".format(message))
            time.sleep(RELOGIN_TIMEOUT)
            continue
        else:
            ctx.logger.info("{0} successful.".format(message))
            return True
    return False


def delete_properties(ctx):
    # cleanup runtime properties
    # need to convert generaton to list, python 3
    keys = [key for key in ctx.instance.runtime_properties.keys()]
    for key in keys:
        del ctx.instance.runtime_properties[key]


def combine_properties(ctx, kwargs=None, names=None, properties=None):
    """combine properties + runtime properties + kwargs"""
    if not kwargs:
        kwargs = {}
    if not properties:
        properties = []
    # add default properties names (uncombined things)
    properties += ["use_external_resource", "resource_id"]
    obj = {}
    # use node properties as base
    obj.update(ctx.node.properties)
    if names:
        # update base properties with runtime properties
        for name in names:
            prop_value = obj.get(name, {})
            prop_value.update(ctx.instance.runtime_properties.get(name, {}))
            obj[name] = prop_value
        # update base properties with kwargs
        for name in names:
            prop_value = obj.get(name, {})
            prop_value.update(kwargs.get(name, {}))
            obj[name] = prop_value
    # combine by priority
    for name in ["use_external_resource", "resource_id"]:
        obj[name] = kwargs.get(
            name,
            ctx.instance.runtime_properties.get(
                name,
                ctx.node.properties.get(name)
            )
        )
    # update runtime properties back
    for name in obj:
        if "vcloud_config" != name:
            ctx.instance.runtime_properties[name] = obj[name]
    return obj
