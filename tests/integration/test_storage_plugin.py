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


class VolumeTestCase(TestCase):
    def setUp(self):
        super(VolumeTestCase, self).setUp()

    @fail_guard
    def test_new(self):
        self.init('volume_new.yaml')
        self.install()
        self.uninstall()

    @fail_guard
    def test_use_external(self):
        status, disk = self.vca_client.add_disk(self.conf.vdc, self.conf.volume_name, self.conf.volume_size_Mb)
        self.init('volume_use_external.yaml')
        self.install()
        self.uninstall()
        self.vca_client = self.get_client()
        status, task = self.vca_client.delete_disk(self.conf.vdc, self.conf.volume_name)
        if status:
            wait_for_task(self.vca_client, task)

    @fail_guard
    def test_attach(self):
        self.init('volume_attach.yaml')
        self.install()
        self.uninstall()
