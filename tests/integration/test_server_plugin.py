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

from tests.integration import TestCase, wait_for_task, fail_guard


class ServerTestCase(TestCase):
    def setUp(self):
        super(ServerTestCase, self).setUp()

    @fail_guard
    def test_with_name(self):
        self.init('server_with_name.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_without_name(self):
        self.init('server_without_name.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_use_external(self):
        task = self.vca_client.create_vapp(self.conf.vdc, self.conf.server_name, self.conf.template,
                                           self.conf.catalog, network_name=self.conf.network_name,
                                           vm_name=self.conf.server_name, deploy='false', poweron='false')
        if task:
            wait_for_task(self.vca_client, task)
        else:
            raise Exception("Can't create vm")
        try:
            self.init('server_use_external.yaml')
            self.install()
            self.uninstall()
        finally:
            self.vca_client.delete_vapp(self.conf.vdc, self.conf.server_name)
        self.failed = False

    @fail_guard
    def test_interface_inputs(self):
        self.init('server_use_interface_inputs.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_connect_to_network(self):
        self.init('server_to_network.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_connect_to_port(self):
        self.init('server_to_port.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_connect_to_many_ports(self):
        self.init('server_to_many_ports.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_remove_keys(self):
        self.init('server_remove_keys.yaml')
        self.install()
        self.uninstall()


class VdcTestCase(TestCase):
    def setUp(self):
        super(VdcTestCase, self).setUp()

    @fail_guard
    def test_new(self):
        if self.service_type == 'subscription':
            print 'Testing only in ondemand service'
            return
        self.init('vdc_new.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_use_external(self):
        task = self.vca_client.create_vdc(self.conf.test_vdc_name)
        if task:
            wait_for_task(self.vca_client, task)
        else:
            raise Exception("Can't create vdc")
        self.init('vdc_use_external.yaml')
        self.install()
        self.uninstall()
        self.vca_client = self.get_client()
        result, task = self.vca_client.delete_vdc(self.conf.test_vdc_name)
        if not result:
            raise Exception(task)
        wait_for_task(self.vca_client, task)
