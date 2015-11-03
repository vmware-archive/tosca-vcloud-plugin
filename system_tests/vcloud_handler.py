# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
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

from cosmo_tester.framework.handlers import (
    BaseHandler,
    BaseCloudifyInputsConfigReader)
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType
from pyvcloud import vcloudair
import time
import requests


TEST_VDC = "systest"

class VcloudCleanupContext(BaseHandler.CleanupContext):

    def __init__(self, context_name, env):
        super(VcloudCleanupContext, self).__init__(context_name, env)

    @classmethod
    def clean_all(cls, env):
        """
        Cleans *all* resources, including resources that were not
        created by the test
        """
        import pdb; pdb.set_trace()
        super(OpenstackCleanupContext, cls).clean_all(env)
        #delete test VDC


class CloudifyVcloudInputsConfigReader(BaseCloudifyInputsConfigReader):

    def __init__(self, cloudify_config, manager_blueprint_path, **kwargs):
        super(CloudifyVcloudInputsConfigReader, self).__init__(
            cloudify_config, manager_blueprint_path=manager_blueprint_path,
            **kwargs)

    @property
    def vcloud_username(self):
        return self.config['vcloud_username']

    @property
    def vcloud_password(self):
        return self.config['vcloud_password']

    @property
    def vcloud_url(self):
        return self.config['vcloud_url']

    @property
    def vcloud_service(self):
        return self.config['vcloud_service']

    @property
    def vcloud_org(self):
        return self.config['vcloud_org']

    @property
    def vcloud_vdc(self):
        return self.config['vcloud_vdc']

    @property
    def manager_server_name(self):
        return self.config['server_name']

    @property
    def manager_server_catalog(self):
        return self.config['catalog']

    @property
    def manager_server_template(self):
        return self.config['template']

    @property
    def management_network_use_existing(self):
        return self.config['management_network_use_existing']

    @property
    def management_network_name(self):
        return self.config['management_network_name']

    @property
    def edge_gateway(self):
        return self.config['edge_gateway']

    @property
    def floating_ip_public_ip(self):
        return self.config['floating_ip_public_ip']

    @property
    def manager_private_key_path(self):
        return self.config['manager_private_key_path']

    @property
    def agent_private_key_path(self):
        return self.config['agent_private_key_path']

    @property
    def manager_public_key(self):
        return self.config['manager_public_key']

    @property
    def agent_public_key(self):
        return self.config['user_public_key']

    @property
    def management_port_ip_allocation_mode(self):
        return self.config['management_port_ip_allocation_mode']

    @property
    def vcloud_service_type(self):
        return self.config['vcloud_service_type']

    @property
    def vcloud_region(self):
        return self.config['vcloud_region']


class VcloudHandler(BaseHandler):
    CleanupContext = VcloudCleanupContext
    CloudifyConfigReader = CloudifyVcloudInputsConfigReader

    def before_bootstrap(self):
        super(VcloudHandler, self).before_bootstrap()
        vca = login(self.env.cloudify_config)
        if vca.get_vdc(TEST_VDC):
            task = vca.delete_vdc(TEST_VDC)
            wait_for_task(vca, task)
        if vca:
            task = vca.create_vdc(TEST_VDC)
            wait_for_task(vca, task)
        else:
            raise RuntimeError("Can't create test VDC")

handler = VcloudHandler


def login(env):
    vca = vcloudair.VCA(
            host=env['vcloud_url'],
            username=env['vcloud_username'],
            service_type=env['vcloud_service_type'],
            version="5.7",
            verify=False)
    logined = (vca.login(env['vcloud_password']) and
               vca.login_to_instance(env['vcloud_instance'], env['vcloud_password']) and
               vca.login_to_instance(env['vcloud_instance'], None, vca.vcloud_session.token, vca.vcloud_session.org_url))
    if logined:
        return vca
    else:
        return None

def wait_for_task(vca_client, task):
    TASK_RECHECK_TIMEOUT = 5
    TASK_STATUS_SUCCESS = 'success'
    TASK_STATUS_ERROR = 'error'

    WAIT_TIME_MAX_MINUTES = 30
    MAX_ATTEMPTS = WAIT_TIME_MAX_MINUTES * 60 / TASK_RECHECK_TIMEOUT
    status = task.get_status()
    for attempt in xrange(MAX_ATTEMPTS):
        if status == TASK_STATUS_SUCCESS:
            return
        if status == TASK_STATUS_ERROR:
            error = task.get_Error()
            raise RuntimeError(
                "Error during task execution: {0}".format(error.get_message()))
        time.sleep(TASK_RECHECK_TIMEOUT)
        response = requests.get(
            task.get_href(),
            headers=vca_client.vcloud_session.get_vcloud_headers(),
            verify=False)
        task = taskType.parseString(response.content, True)
        status = task.get_status()
    raise RuntimeError("Wait for task timeout.")

