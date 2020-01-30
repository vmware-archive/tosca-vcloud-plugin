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
import test_mock_base
from vcloud_network_plugin import network


class NetworkPluginNetworkSubroutesMockTestCase(test_mock_base.TestBase):

    def test__get_network_list(self):
        # check list with one network
        fake_client = self.generate_client(vdc_networks=['something'])
        self.assertEqual(
            ['something'],
            network._get_network_list(fake_client, 'vdc_name')
        )
        fake_client.get_vdc.assert_called_with('vdc_name')
        # can't get vdc
        fake_client.get_vdc = mock.MagicMock(return_value=None)
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._get_network_list(fake_client, 'vdc_name')

    def test_split_adresses(self):
        range_network = network._split_adresses("10.1.1.1-10.1.1.255")
        self.assertEqual(range_network.start, '10.1.1.1')
        self.assertEqual(range_network.end, '10.1.1.255')
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._split_adresses("10.1.1.1")
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._split_adresses("10.1.1.255-10.1.1.1")
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._split_adresses("my-10")

    def test__dhcp_operation(self):
        fake_client = self.generate_client()
        # no dhcp
        fake_ctx = self.generate_node_context(properties={
            'network': {
                'edge_gateway': 'gateway'
            },
            'vcloud_config': {
                'vdc': 'vdc_name'
            }
        })
        with mock.patch('vcloud_network_plugin.network.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                network._dhcp_operation(
                    fake_client, fake_ctx.node.properties,
                    '_management_network', network.ADD_POOL
                )
        # wrong dhcp_range
        fake_ctx = self.generate_node_context(properties={
            'network': {
                'dhcp': {
                    'dhcp_range': ""
                },
                'edge_gateway': 'gateway'
            },
            'vcloud_config': {
                'vdc': 'vdc_name'
            }
        })
        with mock.patch('vcloud_network_plugin.network.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, fake_ctx.node.properties,
                        '_management_network', network.ADD_POOL
                    )

        fake_ctx = self.generate_node_context(properties={
            'network': {
                'dhcp': {
                    'dhcp_range': "10.1.1.1-10.1.1.255"
                },
                'edge_gateway': 'gateway'
            },
            'vcloud_config': {
                'vdc': 'vdc_name'
            }
        })

        with mock.patch('vcloud_network_plugin.network.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                # returned error/None from server
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, fake_ctx.node.properties,
                        '_management_network', network.ADD_POOL
                    )
                fake_client.get_gateway.assert_called_with(
                    'vdc_name', 'gateway'
                )

                # returned error/None from server delete
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, fake_ctx.node.properties,
                        '_management_network', network.DELETE_POOL
                    )

                # returned busy, try next time
                self.set_gateway_busy(fake_client._vdc_gateway)
                self.prepare_retry(fake_ctx)

                self.assertFalse(network._dhcp_operation(
                    fake_client, fake_ctx.node.properties,
                    '_management_network', network.DELETE_POOL
                ))

                # no such gateway
                fake_client.get_gateway = mock.MagicMock(return_value=None)
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, fake_ctx.node.properties,
                        '_management_network', network.ADD_POOL
                    )


if __name__ == '__main__':
    unittest.main()
