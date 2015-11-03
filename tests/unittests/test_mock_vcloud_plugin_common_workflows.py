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

import mock

from tests.unittests import test_mock_base
import vcloud_plugin_common
import vcloud_plugin_common.workflows


class VcloudPluginCommonWorkflowsMockTestCase(test_mock_base.TestBase):

    def _generate_instance(self):
        fake_instance = mock.Mock()
        fake_instance._node_instance = {
            'runtime_properties': {
            },
            'version': None
        }
        fake_instance.id = "fake_instance"
        return fake_instance

    def check_instance(self, call_function, fake_instance):
        call_function.assert_called_with(
            fake_instance._node_instance
        )
        # check for installed token and url
        self.assertEqual(
            fake_instance._node_instance, {
                'runtime_properties': {
                    vcloud_plugin_common.ORG_URL: 'org_url',
                    vcloud_plugin_common.SESSION_TOKEN: 'token'
                },
                'version': 0
            }
        )

    def test_update(self):
        """check update logic"""
        fake_ctx = self.generate_node_context()
        fake_instance = self._generate_instance()
        call_function = mock.MagicMock()
        with mock.patch(
            'vcloud_plugin_common.workflows.update_node_instance',
            call_function
        ):
            vcloud_plugin_common.workflows.update(
                fake_ctx, fake_instance, "token", "org_url"
            )
            self.check_instance(call_function, fake_instance)
        # use local version
        fake_ctx._local = True
        internal = mock.MagicMock()
        update_call = mock.MagicMock()
        internal.handler.storage.update_node_instance = update_call
        fake_ctx._internal = internal
        vcloud_plugin_common.workflows.update(
            fake_ctx, fake_instance, "token", "org_url"
        )
        update_call.assert_called_with(
            'fake_instance', 0, {
                'org_url': 'org_url',
                'session_token': 'token'
            }, None
        )

    def test_get_all_nodes_instances(self):
        """update all instances in context"""
        fake_ctx = self.generate_node_context()
        fake_instance = self._generate_instance()
        call_function = mock.MagicMock()
        # create fake node with all prpoerties
        fake_node = mock.MagicMock()
        fake_node.properties = {
            vcloud_plugin_common.VCLOUD_CONFIG: 'some_magic_here'
        }
        fake_node.instances = [fake_instance]
        fake_ctx._nodes = [fake_node]
        # try to run
        with mock.patch(
            'vcloud_plugin_common.workflows.update_node_instance',
            call_function
        ):
            vcloud_plugin_common.workflows._get_all_nodes_instances(
                fake_ctx, "token", "org_url"
            )
            self.check_instance(call_function, fake_instance)
