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
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import mock
import unittest

from cloudify import exceptions as cfy_exc
from cloudify import mocks as cfy_mocks
from server_plugin import server
from tests.unittests import test_mock_base


class ServerPluginServerSubRoutesMockTestCase(test_mock_base.TestBase):

    def test_check_hardware_empty(self):
        ''' nosing is set '''
        server._check_hardware(None, None)

    def test_check_hardware_without_cpu(self):
        ''' without cpu? '''
        with self.assertRaises(cfy_exc.NonRecoverableError):
            server._check_hardware(0, 10)

    def test_check_hardware_much_cpu(self):
        ''' too mane cpu: 128 cpu? '''
        with self.assertRaises(cfy_exc.NonRecoverableError):
            server._check_hardware(128, 10)

    def test_check_hardware_cpu_is_string(self):
        ''' cpu is string '''
        with self.assertRaises(cfy_exc.NonRecoverableError):
            server._check_hardware('not int', 10)

    def test_check_hardware_low_memory(self):
        ''' low memory == 10M '''
        with self.assertRaises(cfy_exc.NonRecoverableError):
            server._check_hardware(1, 10)

    def test_check_hardware_much_memory(self):
        ''' too much memory 1000G '''
        with self.assertRaises(cfy_exc.NonRecoverableError):
            server._check_hardware(1, 1024 * 1024)

    def test_check_hardware_memory_is_string(self):
        ''' memory is string '''
        with self.assertRaises(cfy_exc.NonRecoverableError):
            server._check_hardware(1, 'memory')

    def test_check_hardware(self):
        server._check_hardware(1, 512)

    def test_get_management_network_name_in_properties(self):
        ''' exist some managment network name in properties '''
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'management_network': '_management_network'
            })
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            self.assertEqual(
                '_management_network',
                server._get_management_network_from_node()
            )

    def test_get_management_network_name_without_properties(self):
        ''' without name in properties '''
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={})
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server._get_management_network_from_node()

    def test_get_management_network_name_in_provider_context(self):
        ''' with name in provider_context '''
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={},
            provider_context={
                'resources': {
                    'int_network': {
                        'name': '_management_network'
                    }
                }
            })
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            self.assertEqual(
                '_management_network',
                server._get_management_network_from_node()
            )

    def test_get_management_network_without_name_in_context(self):
        ''' without name in provider_context '''
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={},
            provider_context={
                'resources': {
                    'int_network': {
                        'other_name': '_management_network'
                    }
                }
            })
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.assertEqual(
                    '_management_network',
                    server._get_management_network_from_node()
                )

    def test_build_script(self):
        self.assertEqual(None, server._build_script({}))
        custom = {
            'pre_script': 'pre_script',
            'post_script': 'post_script',
            'public_keys': [{
                'key': True
            }]
        }
        self.assertNotEqual(None, server._build_script(custom))

    def test_build_public_keys_script(self):
        self.assertEqual('', server._build_public_keys_script([]))
        self.assertEqual('', server._build_public_keys_script([
            {'key': False}
        ]))
        self.assertNotEqual('', server._build_public_keys_script([
            {'key': True}
        ]))
        self.assertNotEqual('', server._build_public_keys_script([
            {
                'key': True,
                'user': 'test',
                'home': 'home'
            }
        ]))

    def test_creation_validation_empty_settings(self):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'server': {}
            },
            provider_context={}
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient',
            self.generate_vca()
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.creation_validation(ctx=fake_ctx)

    def test_creation_validation_external_resource(self):
        """
            must run without any errors and check with empty
            server description
        """
        # unknow resource_id
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True
            },
            provider_context={}
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient',
            self.generate_vca()
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.creation_validation(ctx=fake_ctx)
        # with resource_id
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'resource_id': 'ServerName'
            },
            provider_context={}
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient',
            self.generate_vca()
        ):
            server.creation_validation(ctx=fake_ctx)

    def test_creation_validation_settings_wrong_catalog(self):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'server': {
                    'catalog': 'unknow',
                    'template': 'secret'
                }
            },
            provider_context={}
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            self.generate_vca()
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.creation_validation(ctx=fake_ctx)

    def test_creation_validation_settings_wrong_template(self):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'server': {
                    'catalog': 'public',
                    'template': 'unknow'
                }
            },
            provider_context={}
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            self.generate_vca()
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                server.creation_validation(ctx=fake_ctx)

    def test_creation_validation_settings(self):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'server': {
                    'catalog': 'public',
                    'template': 'secret'
                }
            },
            provider_context={}
        )

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            self.generate_vca()
        ):
            server.creation_validation(ctx=fake_ctx)

    def test_isDhcpAvailable(self):
        client = self.generate_client()
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'server': {
                    'catalog': 'unknow',
                    'template': 'secret'
                },
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            },
            provider_context={}
        )

        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                self.assertEqual(
                    True, server._isDhcpAvailable(client, 'bridged')
                )
                self.assertEqual(
                    False, server._isDhcpAvailable(client, 'local')
                )
                self.assertEqual(
                    True, server._isDhcpAvailable(client, 'vdc_name')
                )

    def test_get_connected(self):

        fake_ctx = self.generate_node_context(relation_node_properties={
            "not_test": "not_test"
        })

        self.assertEqual(
            server._get_connected(fake_ctx.instance, "test"), []
        )
        self.assertEqual(
            server._get_connected(fake_ctx.instance, "not_test"),
            [fake_ctx.instance._relationships[0].target]
        )

        fake_ctx.instance._relationships = []
        # test []
        self.assertEqual(
            server._get_connected(fake_ctx.instance, "test"), []
        )

    def test_create_connections_list(self):
        # one connection from port, one from network and
        # one managment_network
        fake_ctx = self.generate_node_context(relation_node_properties={
            "not_test": "not_test",
            'port': {
                'network': 'private_network',
                'ip_address': "1.1.1.1",
                'mac_address': "hex",
                'ip_allocation_mode': 'pool',
                'primary_interface': True
            },
            'network': {
                'name': 'some_network'
            }
        })
        fake_client = self.generate_client()
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                connection = server._create_connections_list(fake_client)
                self.assertEqual(
                    [
                        {
                            'ip_address': '1.1.1.1',
                            'ip_allocation_mode': 'POOL',
                            'mac_address': 'hex',
                            'network': 'private_network',
                            'primary_interface': True
                        }, {
                            'ip_address': None,
                            'ip_allocation_mode': 'POOL',
                            'mac_address': None,
                            'network': 'some_network',
                            'primary_interface': False
                        }, {
                            'ip_address': None,
                            'ip_allocation_mode': 'POOL',
                            'mac_address': None,
                            'network': '_management_network',
                            'primary_interface': False
                        }
                    ], connection
                )
        # one network same as managment + port
        fake_ctx = self.generate_node_context(relation_node_properties={
            "not_test": "not_test",
            'port': {
                'network': '_management_network',
                'ip_address': "1.1.1.1",
                'mac_address': "hex",
                'ip_allocation_mode': 'pool',
                'primary_interface': True
            },
            'network': {
                'name': 'some_network'
            }
        })
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                connection = server._create_connections_list(fake_client)
                self.assertEqual(
                    [
                        {
                            'ip_address': '1.1.1.1',
                            'ip_allocation_mode': 'POOL',
                            'mac_address': 'hex',
                            'network': '_management_network',
                            'primary_interface': True
                        },
                        {
                            'ip_address': None,
                            'ip_allocation_mode': 'POOL',
                            'mac_address': None,
                            'network': 'some_network',
                            'primary_interface': False
                        }
                    ], connection
                )
        # check dhcp, with no dhcp server
        fake_ctx = self.generate_node_context(relation_node_properties={
            "not_test": "not_test",
            'port': {
                'network': '_management_network',
                'ip_address': "1.1.1.1",
                'mac_address': "hex",
                'ip_allocation_mode': 'dhcp',
                'primary_interface': True
            },
            'network': {
                'name': 'some_network'
            }
        })
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    server._create_connections_list(fake_client)
        # only managment node
        fake_ctx.instance._relationships = []
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                connection = server._create_connections_list(fake_client)
                self.assertEqual(
                    [{
                        'ip_address': None,
                        'ip_allocation_mode': 'POOL',
                        'mac_address': None,
                        'network': '_management_network',
                        'primary_interface': True
                    }],
                    connection
                )
        # no networks
        fake_ctx.instance._relationships = []

        def _generate_fake_client_network(vdc_name, network_name):
            return None

        fake_client.get_network = _generate_fake_client_network
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    server._create_connections_list(fake_client)

    def test_get_vm_network_connections(self):
        # one connection from port, one from network and
        # one managment_network

        # empty connection
        fake_vapp = self.generate_vapp([])
        connections = server._get_vm_network_connections(
            fake_vapp
        )
        self.assertEqual([], connections)
        # not connected
        fake_vapp = self.generate_vapp([{
            'is_connected': False,
            'network_name': 'network_name'
        }])
        connections = server._get_vm_network_connections(
            fake_vapp
        )
        self.assertEqual([], connections)
        # connection
        fake_vapp = self.generate_vapp([{
            'is_connected': True,
            'network_name': 'network_name'
        }])
        connections = server._get_vm_network_connections(
            fake_vapp
        )
        self.assertEqual([
            {
                'is_connected': True,
                'network_name': 'network_name'
            }],
            connections
        )

    def test_get_vm_network_connection(self):
        # one connection from port, one from network and
        # one managment_network
        fake_vapp = self.generate_vapp([{
            'is_connected': True,
            'network_name': 'network_name'
        }])
        # exist network
        connection = server._get_vm_network_connection(
            fake_vapp, 'network_name'
        )
        self.assertEqual(
            {
                'is_connected': True,
                'network_name': 'network_name'
            }, connection
        )
        # not exist network
        connection = server._get_vm_network_connection(
            fake_vapp, 'other'
        )
        self.assertEqual(None, connection)

    def test_get_state(self):
        fake_ctx = self.generate_node_context()
        with mock.patch('server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                # connected network_name
                fake_client = self.generate_client([{
                    'is_connected': True,
                    'network_name': 'network_name',
                    'ip': '1.1.1.1'
                }])
                self.assertFalse(server._get_state(fake_client))
                # not connected network_name
                fake_client = self.generate_client([{
                    'is_connected': False,
                    'network_name': 'network_name',
                    'ip': '1.1.1.1'
                }])
                self.assertTrue(server._get_state(fake_client))
                # not ip in connected network_name
                fake_client = self.generate_client([{
                    'is_connected': True,
                    'network_name': 'network_name',
                    'ip': None
                }])
                self.assertFalse(server._get_state(fake_client))
                # with managment_network
                fake_client = self.generate_client([{
                    'is_connected': True,
                    'network_name': '_management_network',
                    'ip': '1.1.1.1'
                }])
                self.assertTrue(server._get_state(fake_client))


if __name__ == '__main__':
    unittest.main()
