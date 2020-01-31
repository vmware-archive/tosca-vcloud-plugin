# Copyright (c) 2015-2020 Cloudify Platform Ltd. All rights reserved
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

from cloudify import exceptions as cfy_exc
from vcloud_server_plugin import vdc
import vcloud_plugin_common
from tests.unittests import test_mock_base


class ServerPluginVdcMockTestCase(test_mock_base.TestBase):

    def test_creation_validation(self):
        """check validation for vdc operations"""
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={}
            )
            # no vdc name
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.creation_validation(ctx=fake_ctx)
            # name exist but someone already created this vdc
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'name': 'not_existed'
                }
            )
            fake_client.get_vdc = mock.MagicMock(
                return_value=mock.MagicMock()
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.creation_validation(ctx=fake_ctx)
            fake_client.get_vdc.assert_called_with('not_existed')
            # everthing fine
            fake_client.get_vdc = mock.MagicMock(return_value=None)
            vdc.creation_validation(ctx=fake_ctx)
            # external but without name
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'use_external_resource': True
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.creation_validation(ctx=fake_ctx)
            # use unexisted vdc
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'use_external_resource': True,
                    'resource_id': 'not_existed'
                }
            )
            fake_client.get_vdc = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.creation_validation(ctx=fake_ctx)
            fake_client.get_vdc.assert_called_with('not_existed')
            # exist everything
            fake_client.get_vdc = mock.MagicMock(
                return_value=mock.MagicMock()
            )
            vdc.creation_validation(ctx=fake_ctx)
            fake_client.get_vdc.assert_called_with('not_existed')

    def test_create(self):
        """check vdc creation operation"""
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # tried to create new vdc on subscription
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'vcloud_config': {
                        'service_type':
                            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                    }
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.create(ctx=fake_ctx)
            # use ondemand
            # use external resource without vdc
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'vcloud_config': {
                        'service_type':
                            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
                    },
                    'use_external_resource': True,
                    'resource_id': 'not_existed'
                }
            )
            fake_client.get_vdc = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.create(ctx=fake_ctx)
            fake_client.get_vdc.assert_called_with('not_existed')
            # successful for create on external resource
            fake_client.get_vdc = mock.MagicMock(
                return_value=mock.MagicMock()
            )
            vdc.create(ctx=fake_ctx)
            # no name for vdc
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'vcloud_config': {
                        'service_type':
                            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
                    },
                    'use_external_resource': False,
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.create(ctx=fake_ctx)
            # create new vdc for deployment
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'vcloud_config': {
                        'service_type':
                            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
                    },
                    'use_external_resource': False,
                    'name': "something"
                }
            )
            # no task returned
            fake_client.create_vdc = mock.MagicMock(
                return_value=None
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.create(ctx=fake_ctx)
            # everything fine
            fake_client.create_vdc = mock.MagicMock(
                return_value=self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                )
            )
            vdc.create(ctx=fake_ctx)

    def test_delete(self):
        """check vdc deletion operation"""
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # external resorce
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'vcloud_config': {
                        'service_type':
                            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
                    },
                    'use_external_resource': True,
                    'resource_id': 'not_existed'
                }
            )
            vdc.delete(ctx=fake_ctx)
            # return fail from delete vdc
            fake_client.delete_vdc = mock.MagicMock(
                return_value=(False, None)
            )
            fake_ctx = self.generate_node_context_with_current_ctx(
                properties={
                    'vcloud_config': {
                        'service_type':
                            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
                    },
                    'use_external_resource': False,
                    'name': "something"
                },
                runtime_properties={
                    vdc.VDC_NAME: "something"
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vdc.delete(ctx=fake_ctx)
            fake_client.delete_vdc.assert_called_with("something")
            self.assertTrue(
                vdc.VDC_NAME in fake_ctx.instance.runtime_properties
            )
            # succesful delete
            fake_client.delete_vdc = mock.MagicMock(
                return_value=(True, self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                ))
            )
            vdc.delete(ctx=fake_ctx)
            self.assertFalse(
                vdc.VDC_NAME in fake_ctx.instance.runtime_properties
            )
