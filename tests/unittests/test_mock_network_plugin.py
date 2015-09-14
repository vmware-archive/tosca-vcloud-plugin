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
import collections

from cloudify import exceptions as cfy_exc
from tests.unittests import test_mock_base
import network_plugin
from network_plugin import utils
import vcloud_plugin_common


class NetworkPluginMockTestCase(test_mock_base.TestBase):

    def test_get_vm_ip(self):
        """
            check get vm ip from conected networks
        """
        fake_client = self.generate_client(vms_networks=[])
        fake_ctx = self.generate_relation_context()
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'edge_gateway': 'some_edge_gateway',
                'vdc': 'vdc_name'
            }
        }
        fake_ctx._source.instance.runtime_properties = {
            network_plugin.VCLOUD_VAPP_NAME: "name"
        }
        # empty connections/no connection name
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                )
        vms_networks = [{
            'is_connected': True,
            'network_name': 'network_name',
            'is_primary': True,
            'ip': '1.1.1.1'
        }]
        fake_client = self.generate_client(vms_networks=vms_networks)
        # not routed
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                )
        # routed
        self.set_network_routed_in_client(fake_client)
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertEqual(
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                ),
                '1.1.1.1'
            )
        # no networks
        fake_client._vapp.get_vms_network_info = mock.MagicMock(
            return_value=[]
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                )
        # no vapp
        fake_client.get_vapp = mock.MagicMock(return_value=None)
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                )

    def test_collectAssignedIps(self):
        """
            get list ips already used in current gateway based on nat
            rules
        """
        # empty gateway
        self.assertEqual(
            network_plugin.collectAssignedIps(None),
            set([])
        )
        # snat
        gateway = self.generate_gateway()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        self.assertEqual(
            network_plugin.collectAssignedIps(gateway),
            set(
                [network_plugin.AssignedIPs(
                    external='internal', internal='external'
                )]
            )
        )
        # dnat
        gateway = self.generate_gateway()
        rule_inlist = self.generate_nat_rule(
            'DNAT', 'external', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[
            rule_inlist
        ])
        self.assertEqual(
            network_plugin.collectAssignedIps(gateway),
            set(
                [network_plugin.AssignedIPs(
                    external='external', internal='internal'
                )]
            )
        )

    def test_getFreeIP(self):
        """
            check list returned list of free ip
        """
        # exist free ip
        gateway = self.generate_gateway()
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.18.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.18.1.1', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        self.assertEqual(
            network_plugin.getFreeIP(gateway),
            '10.18.1.2'
        )
        # no free ips
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1'
        ])
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.getFreeIP(gateway)

    def test_del_ondemand_public_ip(self):
        """
            test release public ip
        """
        fake_client = self.generate_client()
        gateway = self.generate_gateway()
        fake_ctx = self.generate_node_context()
        # can't deallocate ip
        gateway.deallocate_public_ip = mock.MagicMock(return_value=None)
        with mock.patch('network_plugin.wait_for_gateway', mock.MagicMock()):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.del_ondemand_public_ip(
                    fake_client, gateway, '127.0.0.1', fake_ctx)
        gateway.deallocate_public_ip.assert_called_with('127.0.0.1')
        # successfully dropped public ip
        gateway.deallocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        with mock.patch('vcloud_plugin_common.ctx', mock.MagicMock()):
            with mock.patch('network_plugin.wait_for_gateway', mock.MagicMock()):
                network_plugin.del_ondemand_public_ip(
                    fake_client, gateway, '127.0.0.1', fake_ctx)

    def test_save_gateway_configuration(self):
        """
            check reation of out code for different results from server
            on save configuration
        """
        gateway = self.generate_gateway()
        fake_client = self.generate_client()
        # cant save configuration - error in first call
        self.set_services_conf_result(
            gateway, None
        )
        fake_ctx = self.generate_node_context()
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.save_gateway_configuration(
                gateway, fake_client, fake_ctx)
        # error in status
        self.set_services_conf_result(
            gateway, vcloud_plugin_common.TASK_STATUS_ERROR
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            with mock.patch('vcloud_plugin_common.ctx', mock.MagicMock()):
                network_plugin.save_gateway_configuration(
                    gateway, fake_client, fake_ctx)
        # everything fine
        self.set_services_conf_result(
            gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch('vcloud_plugin_common.ctx', mock.MagicMock()):
            self.assertTrue(
                network_plugin.save_gateway_configuration(
                    gateway, fake_client, fake_ctx))
        # server busy
        self.set_services_conf_result(
            gateway, None
        )
        self.set_gateway_busy(gateway)
        self.assertFalse(
            network_plugin.save_gateway_configuration(
                gateway, fake_client, fake_ctx))

    def test_is_network_routed(self):
        """
            check network route state
        """
        fake_client = self.generate_client(
            vms_networks=[{
                'is_connected': True,
                'network_name': 'network_name',
                'is_primary': True,
                'ip': '1.1.1.1'
            }]
        )
        fake_ctx = self.generate_node_context()
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            # not routed by nat
            network = self.generate_fake_client_network("not_routed")
            fake_client.get_network = mock.MagicMock(return_value=network)
            self.assertFalse(
                network_plugin.is_network_routed(
                    fake_client, 'network_name',
                    fake_client._vdc_gateway
                )
            )
            # nat routed
            self.set_network_routed_in_client(fake_client)
            self.assertTrue(
                network_plugin.is_network_routed(
                    fake_client, 'network_name',
                    fake_client._vdc_gateway
                )
            )
            # nat routed but for other network
            self.assertFalse(
                network_plugin.is_network_routed(
                    fake_client, 'other_network_name',
                    fake_client._vdc_gateway
                )
            )

    def test_get_vapp_name(self):
        """
            check get vapp name
        """
        self.assertEqual(
            network_plugin.get_vapp_name({
                network_plugin.VCLOUD_VAPP_NAME: "name"
            }),
            "name"
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.get_vapp_name({
                "aa": "aaa"
            })

    def test_check_port(self):
        """
            check port
        """
        # port int
        utils.check_port(10)
        # port int to big
        with self.assertRaises(cfy_exc.NonRecoverableError):
            utils.check_port(utils.MAX_PORT_NUMBER + 1)
        # port any
        utils.check_port('any')
        # port not any and not int
        with self.assertRaises(cfy_exc.NonRecoverableError):
            utils.check_port('some')

    def test_CheckAssignedExternalIp(self):
        """
            Check assigned external ip
        """
        gateway = self.generate_gateway()
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.1.1.1', '10.1.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.1.1.1', 'any', '123.1.1.1', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        # free ip
        network_plugin.CheckAssignedExternalIp(
            '10.10.1.2', gateway
        )
        # assigned ip
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.CheckAssignedExternalIp(
                '10.1.1.1', gateway
            )

    def test_CheckAssignedInternalIp(self):
        """
            Check assigned internal ip
        """
        gateway = self.generate_gateway()
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.1.1.1', '10.1.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.1.1.1', 'any', '123.1.1.1', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        # free ip
        network_plugin.CheckAssignedInternalIp(
            '123.1.1.2', gateway
        )
        # assigned ip
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.CheckAssignedInternalIp(
                '123.1.1.1', gateway
            )

    def test_get_gateway(self):
        """
            check get gateway
        """
        # good case
        fake_client = self.generate_client()
        fake_ctx = self.generate_node_context()
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertEqual(
                network_plugin.get_gateway(
                    fake_client, 'test name'
                ),
                fake_client._vdc_gateway
            )
        fake_client.get_gateway.assert_called_with(
            'vdc_name', 'test name'
        )
        # bad case
        fake_client = self.generate_client()
        fake_ctx = self.generate_node_context()
        fake_client.get_gateway = mock.MagicMock(return_value=None)
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_gateway(
                    fake_client, 'test name'
                )

    def test_get_network(self):
        """
            check get network
        """
        # good case
        fake_client = self.generate_client()
        fake_ctx = self.generate_node_context()
        fake_network = self.generate_fake_client_network(
            'test name'
        )
        fake_client.get_network = mock.MagicMock(
            return_value=fake_network
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertEqual(
                network_plugin.get_network(
                    fake_client, 'test name'
                ),
                fake_network
            )
        fake_client.get_network.assert_called_with(
            'vdc_name', 'test name'
        )
        # bad case network not exist
        fake_client = self.generate_client()
        fake_ctx = self.generate_node_context()
        fake_client.get_network = mock.MagicMock(return_value=None)
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_network(
                    fake_client, 'test name'
                )
        # worse case = nework == None
        fake_client = self.generate_client()
        fake_ctx = self.generate_node_context()
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_network(
                    fake_client, None
                )

    def test_get_network_name(self):
        """
            check get network name
        """
        # external without resource_id
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.get_network_name({
                'use_external_resource': True
            })
        # exteranal with resource_id
        self.assertEqual(
            network_plugin.get_network_name({
                'use_external_resource': True,
                'resource_id': 'some_text'
            }),
            'some_text'
        )
        # internal, without network
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.get_network_name({})
        # network without name
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.get_network_name({
                'network': {
                    'name': None
                }
            })
        # good case
        self.assertEqual(
            network_plugin.get_network_name({
                'network': {
                    'name': 'good_text'
                }
            }),
            'good_text'
        )

    def test_check_protocol(self):
        """
            check default protocols
        """
        for protocol in utils.VALID_PROTOCOLS:
            self.assertEqual(
                protocol.capitalize(),
                utils.check_protocol(protocol).capitalize()
            )
        # something unknow
        with self.assertRaises(cfy_exc.NonRecoverableError):
            utils.check_protocol("Unknow").capitalize()

    def test_get_ondemand_public_ip(self):
        """
            check allocate public ip for ondemand
        """
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client()
        # empty result from server
        fake_client._vdc_gateway.allocate_public_ip = mock.MagicMock(
            return_value=None
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_ondemand_public_ip(
                    fake_client, fake_client._vdc_gateway, fake_ctx
                )
        # success allocate ips, but empty list of ips
        fake_client._vdc_gateway.allocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_ondemand_public_ip(
                    fake_client, fake_client._vdc_gateway, fake_ctx
                )
        # exist some new ip
        new_gateway = self.generate_gateway()
        new_gateway.get_public_ips = mock.MagicMock(
            return_value=['1.1.1.1']
        )
        fake_client.get_gateways = mock.MagicMock(
            return_value=[new_gateway]
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertEqual(
                network_plugin.get_ondemand_public_ip(
                    fake_client, fake_client._vdc_gateway, fake_ctx
                ),
                '1.1.1.1'
            )

    def test_get_public_ip_subscription(self):
        """
            check allocate public ip / subscription
        """
        gateway = self.generate_gateway()
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.18.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.18.1.1', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        fake_ctx = self.generate_node_context()
        # for subscription we dont use client
        self.assertEqual(
            network_plugin.get_public_ip(
                None, gateway,
                vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE, fake_ctx
            ),
            '10.18.1.2'
        )

    def test_get_public_ip_ondemand(self):
        """
            check allocate public ip / ondemand
        """
        # ondemand
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client()
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(
            return_value=[]
        )
        fake_client._vdc_gateway.allocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        new_gateway = self.generate_gateway()
        new_gateway.get_public_ips = mock.MagicMock(
            return_value=['10.18.1.21']
        )
        fake_client.get_gateways = mock.MagicMock(
            return_value=[new_gateway]
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertEqual(
                network_plugin.get_public_ip(
                    fake_client, fake_client._vdc_gateway,
                    vcloud_plugin_common.ONDEMAND_SERVICE_TYPE, fake_ctx
                ),
                '10.18.1.21'
            )

    def test_check_ip(self):
        """
            check ip code
        """
        # wrong type
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.check_ip({'wrong': None})
        # wrong value
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network_plugin.check_ip("1.1.1.400")
        # good case
        self.assertEqual(
            network_plugin.check_ip("1.1.1.40"),
            "1.1.1.40"
        )

    def test_is_valid_ip_range(self):
        """
            check ip range
        """
        # wrong range
        self.assertFalse(
            network_plugin.is_valid_ip_range("1.1.1.50", "1.1.1.40")
        )
        # good case
        self.assertTrue(
            network_plugin.is_valid_ip_range("1.1.1.40", "1.1.1.50")
        )

    def test_is_network_exists(self):
        """
            check network exist
        """
        # network exist
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client()
        fake_client.get_network = mock.MagicMock(
            return_value=self.generate_fake_client_network('test')
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertTrue(
                network_plugin.is_network_exists(fake_client, 'test')
            )
        fake_client.get_network.assert_called_with('vdc_name', 'test')
        # network not exist
        fake_ctx = self.generate_node_context()
        fake_client = self.generate_client()
        fake_client.get_network = mock.MagicMock(
            return_value=None
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertFalse(
                network_plugin.is_network_exists(fake_client, 'test')
            )

    def test_is_ips_in_same_subnet(self):
        """
            ips in same net
        """
        # ips from several networks
        self.assertFalse(
            network_plugin.is_ips_in_same_subnet(
                ['123.11.1.1', '123.11.3.1'], 24
            )
        )
        # ips from same network
        self.assertTrue(
            network_plugin.is_ips_in_same_subnet(
                ['123.11.1.1', '123.11.1.1'], 24
            )
        )

    def test_is_separate_ranges(self):
        """
            ips in separate ranges
        """
        IPRange = collections.namedtuple('IPRange', 'start end')
        # positive case
        self.assertTrue(
            network_plugin.is_separate_ranges(
                IPRange(start='1.1.1.1', end='1.1.1.11'),
                IPRange(start='1.1.1.12', end='1.1.1.23')
            )
        )
        # negative case
        self.assertFalse(
            network_plugin.is_separate_ranges(
                IPRange(start='1.1.1.1', end='1.1.1.15'),
                IPRange(start='1.1.1.9', end='1.1.1.23')
            )
        )


if __name__ == '__main__':
    unittest.main()
