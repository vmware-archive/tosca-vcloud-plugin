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
from tests.unittests import test_mock_base
from network_plugin import network
import vcloud_plugin_common


class NetworkPluginNetworkMockTestCase(test_mock_base.TestBase):

    def test_delete(self):
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.1-10.1.1.255"
                        },
                        'edge_gateway': 'gateway'
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                    'use_external_resource': True
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )

            network.delete(ctx=fake_ctx)
            self.assertFalse(
                network.VCLOUD_NETWORK_NAME in
                fake_ctx.instance.runtime_properties
            )

            fake_ctx = self.generate_node_context(
                properties={
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.1-10.1.1.255"
                        },
                        'edge_gateway': 'gateway',
                        'name': 'secret_network'
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                    'use_external_resource': False
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            # error in save_config
            self.set_services_conf_result(
                fake_client._vdc_gateway,
                vcloud_plugin_common.TASK_STATUS_ERROR
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.delete(ctx=fake_ctx)
            # None in deleted vdc network
            self.set_services_conf_result(
                fake_client._vdc_gateway,
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.delete(ctx=fake_ctx)
            # Error in deleted vdc network
            task_delete_vdc = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_ERROR
            )
            fake_client.delete_vdc_network = mock.MagicMock(
                return_value=(True, task_delete_vdc)
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.delete(ctx=fake_ctx)
            fake_client.delete_vdc_network.assert_called_with(
                'vdc_name', 'secret_network'
            )
            # Success in deleted vdc network
            task_delete_vdc = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            fake_client.delete_vdc_network = mock.MagicMock(
                return_value=(True, task_delete_vdc)
            )
            network.delete(ctx=fake_ctx)

    def test_create(self):
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'secret_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                    'use_external_resource': False
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            # error in create_vdc_network
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.create(ctx=fake_ctx)
            fake_client.create_vdc_network.assert_called_with(
                'vdc_name', 'secret_network', 'gateway', '10.1.1.2',
                '10.1.1.127', '10.1.1.1', '255.255.255.0', '8.8.8.8',
                '4.4.4.4', None
            )
            # error in create_vdc_network
            task = self.generate_task(
                vcloud_plugin_common.TASK_STATUS_ERROR
            )
            fake_client.create_vdc_network = mock.MagicMock(
                return_value=(True, task)
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.create(ctx=fake_ctx)
            # success in create_vdc_network
            fake_client.create_vdc_network = mock.MagicMock(
                return_value=(
                    True, self.generate_task(
                        vcloud_plugin_common.TASK_STATUS_SUCCESS
                    )
                )
            )
            self.set_services_conf_result(
                fake_client._vdc_gateway,
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            network.create(ctx=fake_ctx)
            # error in get gateway
            fake_client.get_gateway = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.create(ctx=fake_ctx)
            # use external
            fake_ctx = self.generate_node_context(
                properties={
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'secret_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                    'use_external_resource': True,
                    'resource_id': 'secret_network'
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            network.create(ctx=fake_ctx)
            # not extist network
            fake_ctx = self.generate_node_context(
                properties={
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'secret_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                    'use_external_resource': True,
                    'resource_id': 'secret_network'
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            fake_client.get_network = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.create(ctx=fake_ctx)

    def test_create_exist_same_network(self):
        fake_client = self.generate_client(
            vdc_networks=['secret_network']
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # exist same network
            fake_ctx = self.generate_node_context(
                properties={
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'secret_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                    'use_external_resource': False,
                    'resource_id': 'secret_network'
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            fake_client.get_network = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.create(ctx=fake_ctx)

    def test_creation_validation(self):
        fake_client = self.generate_client(
            vdc_networks=['secret_network']
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # network not exist in node properties
            fake_ctx = self.generate_node_context(
                properties={
                    'use_external_resource': False,
                    'resource_id': 'secret_network'
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.creation_validation(ctx=fake_ctx)
            # network already exist
            fake_ctx = self.generate_node_context(
                properties={
                    'use_external_resource': False,
                    'resource_id': 'secret_network',
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'secret_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            fake_client.get_network = mock.MagicMock(return_value=True)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.creation_validation(ctx=fake_ctx)
            fake_client.get_network.assert_called_with(
                'vdc_name', 'secret_network'
            )
            # use external
            fake_ctx = self.generate_node_context(
                properties={
                    'use_external_resource': True,
                    'resource_id': 'secret_network',
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'secret_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            network.creation_validation(ctx=fake_ctx)

    def test_creation_validation_gateway(self):
        fake_client = self.generate_client(
            vdc_networks=['secret_network']
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'use_external_resource': False,
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'private_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            fake_client.get_network = mock.MagicMock(return_value=None)
            network.creation_validation(ctx=fake_ctx)
            fake_client.get_gateway.assert_called_with(
                'vdc_name', 'gateway'
            )

            # no gateway
            fake_client.get_gateway = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.creation_validation(ctx=fake_ctx)

    def test_creation_validation_network_mask(self):
        # test network mask
        fake_client = self.generate_client(
            vdc_networks=['secret_network']
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'use_external_resource': False,
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.128-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.127",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'private_network',
                        "netmask": '255.255.255.255',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            fake_client.get_network = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.creation_validation(ctx=fake_ctx)

    def test_creation_validation_separate_ips(self):
        # test separate ips
        fake_client = self.generate_client(
            vdc_networks=['secret_network']
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'use_external_resource': False,
                    'network': {
                        'dhcp': {
                            'dhcp_range': "10.1.1.10-10.1.1.255"
                        },
                        'static_range': "10.1.1.2-10.1.1.210",
                        'gateway_ip': "10.1.1.1",
                        'edge_gateway': 'gateway',
                        'name': 'private_network',
                        "netmask": '255.255.255.0',
                        "dns": ["8.8.8.8", "4.4.4.4"]
                    },
                    'vcloud_config': {
                        'vdc': 'vdc_name'
                    },
                },
                runtime_properties={
                    'vcloud_network_name': 'secret_network'
                }
            )
            fake_client.get_network = mock.MagicMock(return_value=None)
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network.creation_validation(ctx=fake_ctx)

if __name__ == '__main__':
    unittest.main()
