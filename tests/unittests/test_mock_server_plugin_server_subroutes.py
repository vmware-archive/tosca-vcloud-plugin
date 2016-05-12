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
from cloudify import mocks as cfy_mocks
from vcloud_server_plugin import server
from tests.unittests import test_mock_base
from cloudify.state import current_ctx


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

    def test_build_script(self):
        with mock.patch('vcloud_server_plugin.server._get_connected_keypairs',
                        mock.MagicMock(
                            return_value=[])):
            self.assertEqual(None, server._build_script({}, []))

        custom = {
            'pre_script': 'pre_script',
            'post_script': 'post_script',
            'public_keys': [{
                'key': True
            }]
        }
        with mock.patch('vcloud_server_plugin.server._get_connected_keypairs',
                        mock.MagicMock(
                            return_value=[{'key': 'key'}])):
            self.assertNotEqual(None, server._build_script(custom, []))

    def test_build_public_keys_script(self):
        def script_fun(a, b, c, d, e):
            return a.append("{}{}{}{}".format(b, c, d, e))
        self.assertEqual('', server._build_public_keys_script([], script_fun))
        self.assertEqual('', server._build_public_keys_script([
            {'key': False}
        ], script_fun))
        self.assertNotEqual('', server._build_public_keys_script([
            {'key': True}
        ], script_fun))
        self.assertNotEqual('', server._build_public_keys_script([
            {
                'key': True,
                'user': 'test',
                'home': 'home'
            }
        ], script_fun))

    def test_creation_validation_empty_settings(self):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'server': {}
            },
            provider_context={}
        )
        current_ctx.set(fake_ctx)

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
        current_ctx.set(fake_ctx)

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
        current_ctx.set(fake_ctx)

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
        current_ctx.set(fake_ctx)

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
        current_ctx.set(fake_ctx)

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
        current_ctx.set(fake_ctx)

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
        current_ctx.set(fake_ctx)

        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
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

        fake_ctx = self.generate_node_context_with_current_ctx(
            relation_node_properties={
                "not_test": "not_test"
            }
        )

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
        fake_ctx = self.generate_node_context_with_current_ctx(
            relation_node_properties={
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
            }
        )
        fake_client = self.generate_client()
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
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
        # get network name from first avaible but not primary
        fake_ctx = self.generate_node_context_with_current_ctx(
            relation_node_properties={
                "not_test": "not_test",
                'port': {
                    'network': 'private_network',
                    'ip_address': "1.1.1.1",
                    'mac_address': "hex",
                    'ip_allocation_mode': 'pool',
                    'primary_interface': False
                }
            }
        )
        fake_client = self.generate_client()
        fake_ctx.node.properties['management_network'] = None
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
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
                        }
                    ], connection
                )
        # no connections
        fake_ctx = self.generate_node_context_with_current_ctx(
            relation_node_properties={
                "not_test": "not_test"
            }
        )
        fake_client = self.generate_client()
        fake_ctx.node.properties['management_network'] = None
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    connection = server._create_connections_list(fake_client)
        # one network same as managment + port
        fake_ctx = self.generate_node_context_with_current_ctx(
            relation_node_properties={
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
            }
        )
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
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
        fake_ctx = self.generate_node_context_with_current_ctx(
            relation_node_properties={
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
            }
        )
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    server._create_connections_list(fake_client)
        # only managment node
        fake_ctx.instance._relationships = []
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
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
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
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
        fake_ctx = self.generate_node_context_with_current_ctx()
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                # connected network_name
                fake_client = self.generate_client([{
                    'is_connected': True,
                    'is_primary': False,
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
                    'is_primary': False,
                    'network_name': 'network_name',
                    'ip': None
                }])
                self.assertFalse(server._get_state(fake_client))
                # with managment_network
                fake_client = self.generate_client([{
                    'is_connected': True,
                    'is_primary': True,
                    'network_name': '_management_network',
                    'ip': '1.1.1.1'
                }])
                self.assertTrue(server._get_state(fake_client))

    def test_add_key_script(self):
        commands = []
        server._add_key_script(commands, "~A~", "~B~", "~C~", "~D~")
        self.assertTrue(commands)
        # check create directory .ssh
        self.assertTrue("~A~" in commands[0])
        self.assertTrue("~B~" in commands[0])
        self.assertTrue("~C~" in commands[0])
        # inject value to key file
        self.assertTrue("~C~" in commands[0])
        self.assertTrue("~D~" in commands[1])

    def test_get_connected_keypairs(self):
        # empty list of relationships
        fake_ctx = self.generate_node_context_with_current_ctx()
        fake_ctx.instance._relationships = None
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
            self.assertEqual([], server._get_connected_keypairs())
        # exist some content
        relationship = self.generate_relation_context()
        runtime_properties = {'public_key': "a"}
        relationship.target.instance.runtime_properties = runtime_properties
        fake_ctx.instance._relationships = [relationship]
        with mock.patch('vcloud_server_plugin.server.ctx', fake_ctx):
            self.assertEqual(
                server._get_connected_keypairs(), ["a"]
            )

    def test_is_primary_connection_has_ip(self):
        # no network info at all
        vapp = mock.MagicMock()
        vapp.get_vms_network_info = mock.MagicMock(return_value=False)
        self.assertTrue(server._is_primary_connection_has_ip(vapp))
        # empty list of connections
        vapp.get_vms_network_info = mock.MagicMock(return_value=[None])
        self.assertTrue(server._is_primary_connection_has_ip(vapp))
        # exist connection, but without ip
        vapp.get_vms_network_info = mock.MagicMock(return_value=[[
            {'is_connected': False}
        ]])
        self.assertFalse(server._is_primary_connection_has_ip(vapp))
        # everything connected
        vapp.get_vms_network_info = mock.MagicMock(return_value=[[{
            'is_connected': True,
            'is_primary': True,
            'ip': '127.0.0.1'
        }]])
        self.assertTrue(server._is_primary_connection_has_ip(vapp))
        # connected but to different port
        vapp.get_vms_network_info = mock.MagicMock(return_value=[[{
            'is_connected': True,
            'is_primary': False,
            'ip': '127.0.0.1'
        }, {
            'is_connected': True,
            'is_primary': True,
            'ip': None
        }]])
        self.assertFalse(server._is_primary_connection_has_ip(vapp))

    def test_remove_key_script(self):
        commands = []
        server._remove_key_script(
            commands, "super!", ".ssh!", "somekey", "!**! !@^"
        )
        self.assertEqual(
            commands, [' sed -i /!@^/d somekey']
        )


if __name__ == '__main__':
    unittest.main()
