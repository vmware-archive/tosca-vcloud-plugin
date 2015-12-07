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
import unittest

from cloudify import exceptions as cfy_exc
from vcloud_server_plugin import server
import vcloud_plugin_common
import vcloud_network_plugin
from tests.unittests import test_mock_base


class ServerPluginServerMockTestCase(test_mock_base.TestBase):

    def test_delete_external_resource(self):
        fake_ctx = self.generate_node_context(
            properties={
                'use_external_resource': True
            }
        )
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            server.delete(ctx=fake_ctx)

        self.assertFalse(
            server.VCLOUD_VAPP_NAME in fake_ctx.instance.runtime_properties
        )

    def test_delete(self):
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # no result from delete
            fake_client._vapp.delete = mock.MagicMock(
                return_value=None
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.delete(ctx=fake_ctx)
            fake_client._vapp.delete.assert_called_with()
            self.check_get_vapp(fake_client, 'vapp_name')

            # error
            fake_task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_ERROR
            )
            fake_client._vapp.delete = mock.MagicMock(
                return_value=fake_task
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.delete(ctx=fake_ctx)

            # success
            fake_task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            fake_client._vapp.delete = mock.MagicMock(
                return_value=fake_task
            )
            server.delete(ctx=fake_ctx)
            self.assertFalse(
                server.VCLOUD_VAPP_NAME in fake_ctx.instance.runtime_properties
            )

    def test_stop_external_resource(self):
        fake_ctx = self.generate_node_context(
            properties={
                'use_external_resource': True
            }
        )
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            server.stop(ctx=fake_ctx)

        self.assertTrue(
            server.VCLOUD_VAPP_NAME in fake_ctx.instance.runtime_properties
        )

    def test_stop(self):
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_client._vapp.undeploy = mock.MagicMock(
                return_value=None
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.stop(ctx=fake_ctx)
            fake_client._vapp.undeploy.assert_called_with()
            self.check_get_vapp(fake_client, 'vapp_name')

            # error
            fake_task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_ERROR
            )
            fake_client._vapp.undeploy = mock.MagicMock(
                return_value=fake_task
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.stop(ctx=fake_ctx)

            # success
            fake_task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            fake_client._vapp.undeploy = mock.MagicMock(
                return_value=fake_task
            )
            server.stop(ctx=fake_ctx)
            self.assertTrue(
                server.VCLOUD_VAPP_NAME in fake_ctx.instance.runtime_properties
            )

    def check_get_vapp(self, fake_client, vapp_name):
        fake_client.get_vdc.assert_called_with('vdc_name')
        fake_client.get_vapp.assert_called_with(
            fake_client._app_vdc, vapp_name
        )

    def test_start(self):
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client([{
            'is_connected': True,
            'is_primary': True,
            'network_name': 'network_name',
            'ip': '1.1.1.1'
        }])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # poweroff with error equal to None
            fake_client._vapp.me.get_status = mock.MagicMock(
                return_value=vcloud_plugin_common.STATUS_POWERED_OFF
            )
            fake_client._vapp.poweron = mock.MagicMock(
                return_value=None
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.start(ctx=fake_ctx)
            fake_client._vapp.poweron.assert_called_with()
            self.check_get_vapp(fake_client, 'vapp_name')

            # poweroff with error in task
            fake_client._vapp.me.get_status = mock.MagicMock(
                return_value=vcloud_plugin_common.STATUS_POWERED_OFF
            )
            fake_task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_ERROR
            )
            fake_client._vapp.poweron = mock.MagicMock(
                return_value=fake_task
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.start(ctx=fake_ctx)

        fake_client = self.generate_client([{
            'is_connected': False,
            'is_primary': False,
            'network_name': 'network_name',
            'ip': '1.1.1.1'
        }])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # poweroff with success in task but not connected
            fake_client._vapp.me.get_status = mock.MagicMock(
                return_value=vcloud_plugin_common.STATUS_POWERED_OFF
            )
            fake_task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            fake_client._vapp.poweron = mock.MagicMock(
                return_value=fake_task
            )
            self.assertEquals(server.start(ctx=fake_ctx), None)

            # poweron with success in task but not connected
            fake_client._vapp.me.get_status = mock.MagicMock(
                return_value=vcloud_plugin_common.STATUS_POWERED_OFF
            )
            self.assertEquals(server.start(ctx=fake_ctx), None)

        fake_client = self.generate_client([{
            'is_connected': True,
            'is_primary': True,
            'network_name': '_management_network',
            'ip': '1.1.1.1'
        }])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # poweron with success in task and connected
            fake_client._vapp.me.get_status = mock.MagicMock(
                return_value=vcloud_plugin_common.STATUS_POWERED_ON
            )
            self.assertEquals(server.start(ctx=fake_ctx), None)

        # use external without any power state changes, run retry
        fake_ctx = self.generate_node_context()
        fake_ctx.node.properties['use_external_resource'] = True
        fake_client = self.generate_client([{
            'is_connected': True,
            'is_primary': True,
            'network_name': '_management_network',
            'ip': None
        }])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.prepare_retry(fake_ctx)
            server.start(ctx=fake_ctx)
            self.check_retry_realy_called(
                fake_ctx,
                "Waiting for VM's configuration to complete", 5
            )

    def test_start_external_resource(self):
        """
            start with external resource, as success status used retry
        """
        fake_ctx = self.generate_node_context(
            properties={
                'use_external_resource': True,
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'management_network': '_management_network'
            }
        )
        fake_client = self.generate_client([{
            'is_connected': True,
            'is_primary': True,
            'network_name': 'network_name',
            'ip': '1.1.1.1'
        }])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.assertEquals(server.start(ctx=fake_ctx), None)

    def test_create_default_values(self):
        """
            test server create with default value and error in request
        """
        fake_ctx = self.generate_node_context(properties={
            'management_network': '_management_network',
            'vcloud_config': {
                'vdc': 'vdc_name'
            },
            'server': {
                'template': 'template',
                'catalog': 'catalog'
            }
        })
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.run_with_statuses(
                fake_client, fake_ctx
            )
            fake_ctx.instance._relationships = None
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)

    def test_create_configure_cpu_mem_values(self):
        """
            check custom cpu/memmory with error in task
        """
        # use existed vm
        fake_ctx = self.generate_node_context(
            properties={
                'management_network': '_management_network',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'use_external_resource': True,
                'resource_id': 'some_server'
            },
            relation_node_properties={
                "not_test": "not_test"
            }
        )
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            server.configure(ctx=fake_ctx)
        # can't get vapp
        fake_ctx = self.generate_node_context(
            properties={
                'management_network': '_management_network',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'server': {
                    'template': 'ubuntu',
                    'catalog': 'public',
                    'hardware': {
                        'cpu': 1,
                        'memory': 512
                    },
                    'guest_customization': {
                        'pre_script': 'pre_script',
                        'post_script': 'post_script',
                        'admin_password': 'pass',
                        'computer_name': 'computer'
                    }
                }
            },
            relation_node_properties={
                "not_test": "not_test"
            }
        )
        fake_client = self.generate_client()
        fake_client.get_vapp = mock.MagicMock(return_value=None)
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)
        # create new vm
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # can't customize memory
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)
            fake_client._vapp.modify_vm_memory.assert_called_with(
                'test', 512
            )
            fake_client._vapp.modify_vm_memory = mock.MagicMock(
                return_value=self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                )
            )

            # can't customize cpu
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)
            fake_client._vapp.modify_vm_cpu.assert_called_with(
                'test', 1
            )
            fake_client._vapp.modify_vm_cpu = mock.MagicMock(
                return_value=self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                )
            )
            fake_client._vapp.modify_vm_name = mock.MagicMock(
                return_value=self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                )
            )

            # need force customization, successfull customization
            fake_client._vapp.customize_on_next_poweron = mock.MagicMock(
                return_value=False
            )
            server.configure(ctx=fake_ctx)

            # somethin wrong with force_customization
            fake_client._vapp.force_customization = mock.MagicMock(
                return_value=None
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)

            # everything fine
            fake_client._vapp.customize_on_next_poweron = mock.MagicMock(
                return_value=True
            )
            server.configure(ctx=fake_ctx)
            server.create(ctx=fake_ctx)
            fake_client._vapp.modify_vm_name.assert_called_with(
                1, 'test'
            )

            # we dont have connected ip
            fake_client._vapp.get_vms_network_info = mock.MagicMock(
                return_value=[[{'is_connected': False}]]
            )
            fake_client._vapp.me.get_status = mock.MagicMock(
                return_value=vcloud_plugin_common.STATUS_POWERED_ON
            )
            sleep_mock = mock.MagicMock()
            with mock.patch(
                'time.sleep',
                sleep_mock
            ):
                server.configure(ctx=fake_ctx)
            sleep_mock.assert_called_with(
                vcloud_network_plugin.GATEWAY_TIMEOUT
            )
            # after first run we have ip
            vapp_with_network = mock.MagicMock()
            vapp_with_network.get_vms_network_info = mock.MagicMock(
                return_value=[[{
                    'is_connected': True,
                    'is_primary': True,
                    'network_name': 'network_name',
                    'ip': '1.1.1.1'
                }]]
            )
            fake_client.get_vapp = mock.MagicMock(
                side_effect=[fake_client._vapp, vapp_with_network]
            )
            with mock.patch(
                'time.sleep',
                sleep_mock
            ):
                server.configure(ctx=fake_ctx)

    def check_create_call(self, fake_client, fake_ctx, positive=True):
        fake_client.create_vapp.assert_called_with(
            'vdc_name', 'test', 'template', 'catalog'
        )

        self.assertEqual(
            positive,
            server.VCLOUD_VAPP_NAME in fake_ctx.instance.runtime_properties
        )

    def run_with_statuses(
        self, fake_client, fake_ctx,
        create_app=None, modify_vm_name=None,
        connect_to_network=None, connect_vms=None,
        customize_guest_os=None, force_customization=None
    ):
        fake_task = None
        if create_app:
            fake_task = self.generate_task(create_app)
        fake_client.create_vapp = mock.MagicMock(
            return_value=fake_task
        )

        fake_modify_vm_name = None
        if modify_vm_name:
            fake_modify_vm_name = self.generate_task(modify_vm_name)
        fake_client._vapp.modify_vm_name = mock.MagicMock(
            return_value=fake_modify_vm_name
        )

        fake_task_network = None
        if connect_to_network:
            fake_task_network = self.generate_task(connect_to_network)
        fake_client._vapp.connect_to_network = mock.MagicMock(
            return_value=fake_task_network
        )

        fake_task_link = None
        if connect_vms:
            fake_task_link = self.generate_task(connect_vms)
        fake_client._vapp.connect_vms = mock.MagicMock(
            return_value=fake_task_link
        )

        fake_task_customize = None
        if customize_guest_os:
            fake_task_customize = self.generate_task(customize_guest_os)
        fake_client._vapp.customize_guest_os = mock.MagicMock(
            return_value=fake_task_customize
        )

        fake_force_customization = None
        if force_customization:
            fake_force_customization = self.generate_task(force_customization)
        fake_client._vapp.force_customization = mock.MagicMock(
            return_value=fake_force_customization
        )

    def generate_context_for_create(self):
        return self.generate_node_context(
            properties={
                'management_network': '_management_network',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'server': {
                    'template': 'template',
                    'catalog': 'catalog'
                }
            },
            relation_node_properties={
                "not_test": "not_test"
            }
        )

    def generate_context_for_customization(self):
        return self.generate_node_context(
            properties={
                'management_network': '_management_network',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'server': {
                    'template': 'template',
                    'catalog': 'catalog',
                    'guest_customization': {
                        'pre_script': 'pre_script',
                        'post_script': 'post_script',
                        'public_keys': [{
                            'key': True
                        }]
                    }
                }
            },
            relation_node_properties={
                "not_test": "not_test"
            }
        )

    def test_create_external_resource(self):
        """
            must run without any errors
        """
        fake_ctx = self.generate_node_context(
            properties={
                'use_external_resource': True,
                'resource_id': 'ServerName',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
            }
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient',
            self.generate_vca()
        ):
            server.create(ctx=fake_ctx)
        self.assertTrue(
            server.VCLOUD_VAPP_NAME in fake_ctx.instance.runtime_properties
        )
        self.assertTrue(
            fake_ctx.instance.runtime_properties[server.VCLOUD_VAPP_NAME],
            'ServerName'
        )

    def test_create_connection_error(self):
        """
            test server create with default value and success in request
        """
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_ERROR
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)

    def test_create_cant_change_name(self):
        """
            test server create with default value and empty task
            from change name
        """
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)

    def test_create_connection_empty_task(self):
        """
            test server create with default value and empty task
            from connection
        """
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)

    def test_create_cant_get_vapp(self):
        """
            test server create with default value and empty vapp
        """
        # with create
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        fake_client.get_vapp = mock.MagicMock(
            return_value=None
        )
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)
        # use external resource
        fake_ctx.node.properties['use_external_resource'] = True
        fake_ctx.node.properties['resource_id'] = 'someresource'
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)

    def test_create_link_empty(self):
        """
            test server create with default value and empty link
        """
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # link empty
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)

    def test_create_link_error(self):
        """
            test server create with default value and error in link
        """
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_ERROR
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.create(ctx=fake_ctx)
            self.check_create_call(fake_client, fake_ctx)

    def test_create_link_success(self):
        """
            test server create with default value and success in link
        """
        fake_ctx = self.generate_context_for_create()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_client._vapp.modify_vm_name = mock.MagicMock(
                return_value=self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                )
            )
            server.create(ctx=fake_ctx)

    def test_create_customization(self):
        """
            test customization - task None
        """
        fake_ctx = self.generate_context_for_customization()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)

    def test_create_customization_error(self):
        """
            test customization - task error
        """
        fake_ctx = self.generate_context_for_customization()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_ERROR
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)

    def test_create_customization_un_customized(self):
        """
            test customization - uncustomized
        """
        fake_ctx = self.generate_context_for_customization()
        fake_client = self.generate_client()
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        fake_client._vapp.customize_on_next_poweron = mock.MagicMock(
            return_value=None
        )
        fake_client._vapp.force_customization = mock.MagicMock(
            return_value=None
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.configure(ctx=fake_ctx)

    def test_create_customization_customized(self):
        """
            test customization - success customization
        """
        fake_ctx = self.generate_context_for_customization()
        fake_client = self.generate_client()
        fake_client._vapp.customize_on_next_poweron = mock.MagicMock(
            return_value=True
        )
        self.run_with_statuses(
            fake_client, fake_ctx,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            server.configure(ctx=fake_ctx)

if __name__ == '__main__':
    unittest.main()
