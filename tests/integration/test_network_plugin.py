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

from tests.integration import TestCase, fail_guard


class FloatingIpTestCase(TestCase):
    def setUp(self):
        super(self.__class__, self).setUp()

    @fail_guard
    def test_connect(self):
        self.init('floatingip_connect.yaml')
        self.install()
        self.uninstall()


class KeypairTestCase(TestCase):
    def setUp(self):
        super(self.__class__, self).setUp()

    @fail_guard
    def test_create(self):
        self.init('keypair_create.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_connect(self):
        self.init('keypair_connect.yaml')
        self.install()
        self.uninstall()


class NetworkTestCase(TestCase):
    def setUp(self):
        super(self.__class__, self).setUp()

    @fail_guard
    def test_network_new(self):
        self.init('network_new.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_network_use_external(self):
        self.init('network_use_external.yaml')
        self.install()
        self.uninstall()


class PublicNatTestCase(TestCase):
    def setUp(self):
        super(self.__class__, self).setUp()

    @fail_guard
    def test_connect_to_network(self):
        self.init('publicnat_to_network.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_connect_to_server(self):
        self.init('publicnat_to_server.yaml')
        self.install()
        self.uninstall()


class SecurityGroupTestCase(TestCase):
    def setUp(self):
        super(self.__class__, self).setUp()

    @fail_guard
    def test_create(self):
        self.init('security_group_create.yaml')
        self.install()
        self.uninstall()
