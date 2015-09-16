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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from testconfig import config
import mock
import unittest
import shutil
import os
import yaml
import tempfile
import requests
import time
from functools import wraps
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType
from cloudify import mocks as cfy_mocks
from vcloud_plugin_common import Config, VcloudAirClient
import cloudify_cli.commands.local as local_command
import cloudify_cli.logger as logger
from cloudify import exceptions as cfy_exc
SUBSCRIPTION = 'subscription'
ONDEMAND = 'ondemand'
RANDOM_PREFIX_LENGTH = 5


class Objectview(object):
    def __init__(self, d):
        self.__dict__ = d


class IntegrationSubscriptionTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = \
        '~/vcloud_integration_subscription_test_config.yaml'


class IntegrationOndemandTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = \
        '~/vcloud_integration_ondemand_test_config.yaml'


class VcloudSubscriptionTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config_subscription.yaml'


class VcloudOndemandTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config_ondemand.yaml'


class TestCase(unittest.TestCase):

    def __init__(self, testname):
        super(TestCase, self).__init__(testname)
        test_configs = {
            SUBSCRIPTION: (VcloudSubscriptionTestConfig().get(),
                           IntegrationSubscriptionTestConfig().get()),
            ONDEMAND: (VcloudOndemandTestConfig().get(),
                       IntegrationOndemandTestConfig().get())}
        if not config:
            raise RuntimeError(
                "Vcloud Service type not defined."
                "To define service type for tests, add one of command line key"
                " to nosetest command: --tc=ondemand: --tc=subscription:")
        if len(config) != 1:
            raise RuntimeError("Config must contain 1 element")
        self.service_type = config.keys()[0]
        service_config = test_configs.get(self.service_type)
        if not service_config:
            raise RuntimeError(
                "Unknown service_type: {0}. Parameter must one of {1}".
                format(self.service_type, (SUBSCRIPTION, ONDEMAND)))
        self.vcloud_config = service_config[0]
        self.test_config = service_config[1]

        if not self.vcloud_config:
            raise RuntimeError("vcloud_config empty")
        if not self.test_config:
            raise RuntimeError("test_config empty")
        print "\nUsed config: {0}".format(self.service_type)
        self.vca_client = self.get_client()

    def get_client(self):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={})
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            vca_client = VcloudAirClient().get(config=self.vcloud_config)
        return vca_client

    def setUp(self):
        self.inputs = yaml.load(open('blueprints/inputs.yaml'))
        self.inputs.update(self.vcloud_config)
        self.tempdir = tempfile.mkdtemp()
        self.workdir = os.getcwd()
        logger.configure_loggers()
        self.failed = True
        self.conf = Objectview(self.inputs)

    def tearDown(self):
        try:
            if self.failed:
                self.uninstall()
        except Exception as e:
            print e
        os.chdir(self.workdir)
        shutil.rmtree(self.tempdir, True)

    def init(self, blueprint_file):
        blueprint = yaml.load(open('blueprints/header.yaml'))
        nodes = yaml.load(open('blueprints/{}'.format(blueprint_file)))
        blueprint['node_templates'].update(nodes)
        with open(os.path.join(self.tempdir, 'inputs.yaml'), 'w') as f:
            yaml.dump(self.inputs, f)
        with open(os.path.join(self.tempdir, 'blueprint.yaml'), 'w') as f:
            yaml.dump(blueprint, f)
        os.chdir(self.tempdir)
        local_command.init('blueprint.yaml', 'inputs.yaml', False)

    def install(self):
        self._execute_command('install')

    def uninstall(self):
        self._execute_command('uninstall')

    def _execute_command(self, command):
        local_command.execute(command, {}, False, 5, 5, 1)


def fail_guard(f):
    @wraps(f)
    def wrapper(*args, **kargs):
            args[0].failed = True
            f(*args, **kargs)
            args[0].failed = False
    return wrapper


def wait_for_task(vca_client, task):
    """
        check status of current task and make request for recheck
        task status in case when we have not well defined state
        (not error and not success or by timeout)
    """
    WAIT_TIME_MAX_MINUTES = 30
    TASK_RECHECK_TIMEOUT = 5
    TASK_STATUS_SUCCESS = 'success'
    TASK_STATUS_ERROR = 'error'
    MAX_ATTEMPTS = WAIT_TIME_MAX_MINUTES * 60 / TASK_RECHECK_TIMEOUT
    print('Maximun task wait time {0} minutes.'.format(WAIT_TIME_MAX_MINUTES))
    print('Task recheck after {0} seconds.'.format(TASK_RECHECK_TIMEOUT))
    status = task.get_status()
    for attempt in range(MAX_ATTEMPTS):
        print('Attempt: {0}/{1}.'.format(attempt + 1, MAX_ATTEMPTS))
        if status == TASK_STATUS_SUCCESS:
            print('Task completed in {0} seconds'.format(attempt * TASK_RECHECK_TIMEOUT))
            return
        if status == TASK_STATUS_ERROR:
            error = task.get_Error()
            raise cfy_exc.NonRecoverableError(
                "Error during task execution: {0}".format(error.get_message()))
        time.sleep(TASK_RECHECK_TIMEOUT)
        response = requests.get(
            task.get_href(),
            headers=vca_client.vcloud_session.get_vcloud_headers())
        task = taskType.parseString(response.content, True)
        status = task.get_status()
    raise cfy_exc.NonRecoverableError("Wait for task timeout.")
