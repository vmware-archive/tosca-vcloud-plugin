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

import mock
import unittest

from cloudify import exceptions as cfy_exc
from tests.unittests import test_mock_base
from vcloud_network_plugin import public_nat
from vcloud_network_plugin import utils
import vcloud_network_plugin
import vcloud_plugin_common
from IPy import IP


class NetworkPluginPublicNatMockTestCase(test_mock_base.TestBase):

    def test_is_rule_exists(self):
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', '22', 'internal', '11', 'TCP'
        )
        # exist
        self.assertTrue(
            public_nat._is_rule_exists(
                [rule_inlist], 'SNAT', 'external', '22', 'internal',
                '11', 'TCP')
        )
        # not exist
        self.assertFalse(
            public_nat._is_rule_exists(
                [rule_inlist], 'DNAT', 'external', '22', 'internal',
                '11', 'UDP')
        )

    def test_get_original_port_for_delete(self):
        # no replacement
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {}}

        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.1", "11"),
                "11"
            )
        # replacement for other
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {
                "10.1.1.2:11": '12'
            }
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.1", "11"),
                "11"
            )
        # replacement for other
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {
                "10.1.1.2:11": '12'
            }
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.2", "11"),
                "12"
            )

    def test_get_original_port_for_create(self):
        gateway = mock.Mock()
        fake_ctx = self.generate_relation_context_with_current_ctx()
        rule_inlist = self.generate_nat_rule(
            'DNAT', 'external', 'any', 'internal', '11', 'TCP')
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            # exeption about same port
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat._get_original_port_for_create(
                    gateway, 'DNAT', 'external', 'any', 'internal', '11', 'TCP'
                )
            # everythiong fine with different port
            self.assertEqual(
                public_nat._get_original_port_for_create(
                    gateway, 'DNAT', 'external', '12', 'internal', '12', 'TCP'
                ),
                12)
            # relink some port to other
            # port have not used yet
            self.assertEqual(
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external', 13, 'internal', '12', 'TCP'),
                13)

    def test_get_original_port_for_create_with_ctx(self):
        # with replace, but without replace table - up port +1
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {}
        }
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 10, 'internal', 11, 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external', '10', 'internal', '11', 'TCP'
                ),
                11
            )
            self.assertEqual(
                fake_ctx._target.instance.runtime_properties,
                {
                    public_nat.PORT_REPLACEMENT: {
                        'external:10': 11
                    }
                }
            )
        # same but without replacement at all
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external', '10', 'internal', '11', 'TCP'
                ),
                11
            )
            self.assertEqual(
                fake_ctx._target.instance.runtime_properties,
                {
                    public_nat.PORT_REPLACEMENT: {
                        'external:10': 11
                    }
                }
            )
        # we dont have enought ports
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', utils.MAX_PORT_NUMBER,
            'internal', 11, 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external',
                    utils.MAX_PORT_NUMBER, 'internal', '11', 'TCP'
                )

    def test_get_gateway_ip_range(self):
        gate = mock.Mock()
        # empty list of networks
        gate.get_dhcp_pools = mock.MagicMock(return_value=[])
        self.assertEqual(
            public_nat._get_gateway_ip_range(gate, 'something'),
            None
        )
        # exist other network
        gate.get_dhcp_pools = mock.MagicMock(return_value=[
            self.genarate_pool(
                'test_network', '127.0.0.1', '127.0.0.255'
            )
        ])
        self.assertEqual(
            public_nat._get_gateway_ip_range(gate, 'something'),
            None
        )
        # exist correct network
        self.assertEqual(
            public_nat._get_gateway_ip_range(gate, 'test_network'),
            (IP('127.0.0.1'), IP('127.0.0.255'))
        )

    def test_obtain_public_ip(self):
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        gateway = mock.Mock()
        fake_client = mock.Mock()
        # exist some ip for delete
        self.assertEqual(
            public_nat._obtain_public_ip(
                fake_client, fake_ctx, gateway, vcloud_network_plugin.DELETE
            ),
            '192.168.1.1'
        )
        # no ip for delete
        fake_ctx._target.instance.runtime_properties = {}
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._obtain_public_ip(
                fake_client, fake_ctx, gateway, vcloud_network_plugin.DELETE
            )
        # unknow operation
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._obtain_public_ip(
                fake_client, fake_ctx, gateway, 'unknow operation'
            )
        # exist some public ip
        fake_ctx._target.node.properties = {
            'nat': {
                vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
            }
        }
        self.assertEqual(
            public_nat._obtain_public_ip(
                fake_client, fake_ctx, gateway, vcloud_network_plugin.CREATE
            ),
            '192.168.1.1'
        )
        # no public ip yet
        fake_ctx._target.node.properties = {
            'nat': {}
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'vdc': 'vdc_name',
                'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            }
        }
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.18.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.18.1.1', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                self.assertEqual(
                    public_nat._obtain_public_ip(
                        fake_client, fake_ctx, gateway,
                        vcloud_network_plugin.CREATE
                    ),
                    '10.18.1.2'
                )

    def test_get_network_ip_range(self):
        # dont have ip range for this network
        fake_client = self.generate_client()
        self.assertEqual(
            public_nat._get_network_ip_range(
                fake_client, "some_org", "some_network"
            ),
            None
        )
        fake_client.get_networks.assert_called_with("some_org")
        # different network
        network = self.generate_fake_client_network(
            name="some", start_ip="127.1.1.1", end_ip="127.1.1.255"
        )
        fake_client.get_networks = mock.MagicMock(return_value=[network])
        self.assertEqual(
            public_nat._get_network_ip_range(
                fake_client, "some_org", "some_network"
            ),
            None
        )
        # correct network name
        fake_client.get_networks = mock.MagicMock(return_value=[network])
        self.assertEqual(
            public_nat._get_network_ip_range(
                fake_client, "some_org", "some"
            ),
            (IP('127.1.1.1'), IP('127.1.1.255'))
        )

    def test_create_ip_range(self):
        # context
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._source.instance.runtime_properties = {
            vcloud_network_plugin.network.VCLOUD_NETWORK_NAME: "some"
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'org': 'some_org',
                'vdc': 'some_vdc'
            }
        }
        fake_ctx._target.instance.runtime_properties = {}
        # vca client
        fake_client = self.generate_client()
        # gateway
        gate = fake_client._vdc_gateway
        gate.get_dhcp_pools = mock.MagicMock(return_value=[])
        network = self.generate_fake_client_network(
            name="some", start_ip="127.1.1.100", end_ip="127.1.1.200"
        )
        fake_client.get_networks = mock.MagicMock(return_value=[network])
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                # empty gateway dhcp pool
                # vca pool: 127.1.1.100..127.1.1.200
                self.assertEqual(
                    public_nat._create_ip_range(fake_client, gate),
                    '127.1.1.100 - 127.1.1.200'
                )
                fake_client.get_networks.assert_called_with("some_vdc")
                # network from gate
                gate.get_dhcp_pools = mock.MagicMock(return_value=[
                    self.genarate_pool(
                        "some", '127.1.1.1', '127.1.1.255'
                    )
                ])
                self.assertEqual(
                    public_nat._create_ip_range(fake_client, gate),
                    '127.1.1.1 - 127.1.1.255'
                )
                # network not exist
                network = self.generate_fake_client_network(
                    name="other", start_ip="127.1.1.100",
                    end_ip="127.1.1.200"
                )
                fake_client.get_networks = mock.MagicMock(
                    return_value=[network]
                )
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat._create_ip_range(fake_client, gate)

    def test_save_configuration(self):

        def _context_for_delete(service_type):
            """
                create correct context for delete
            """
            fake_ctx = self.generate_relation_context_with_current_ctx()
            self.set_services_conf_result(
                gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            fake_ctx._target.instance.runtime_properties = {
                vcloud_network_plugin.PUBLIC_IP: "1.2.3.4",
                public_nat.PORT_REPLACEMENT: {
                    '127.0.0.1:10': '100'
                },
                vcloud_network_plugin.SSH_PORT: '23',
                vcloud_network_plugin.SSH_PUBLIC_IP: '10.1.1.1'
            }
            properties = {
                'vcloud_config': {
                    'edge_gateway': 'gateway',
                    'vdc': 'vdc',
                    'org': 'some_org'
                }
            }
            if service_type:
                properties['vcloud_config']['service_type'] = service_type
            fake_ctx._source.node.properties = properties
            return fake_ctx

        def _ip_exist_in_runtime(fake_ctx):
            """
                ip still exist in ctx
            """
            runtime_properties = fake_ctx._target.instance.runtime_properties
            return vcloud_network_plugin.PUBLIC_IP in runtime_properties

        fake_client = self.generate_client()
        gateway = fake_client._vdc_gateway
        # cant save configuration: server busy
        self.set_services_conf_result(
            gateway, None
        )
        self.set_gateway_busy(gateway)
        fake_ctx = self.generate_relation_context_with_current_ctx()
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertFalse(public_nat._save_configuration(
                gateway, fake_client, vcloud_network_plugin.CREATE,
                "1.2.3.4"
            ))

        # operation create
        fake_ctx = self.generate_relation_context_with_current_ctx()
        self.set_services_conf_result(
            gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            # success save configuration
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                public_nat._save_configuration(
                    gateway, fake_client, vcloud_network_plugin.CREATE,
                    "1.2.3.4")
            self.assertEqual(
                fake_ctx._target.instance.runtime_properties,
                {
                    vcloud_network_plugin.PUBLIC_IP: "1.2.3.4"
                }
            )
        # delete - subscription service
        fake_ctx = _context_for_delete(
            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
        )
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, fake_client, vcloud_network_plugin.DELETE,
                    "1.2.3.4"
                )

        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        # delete - without service
        fake_ctx = _context_for_delete(None)
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, fake_client, vcloud_network_plugin.DELETE,
                    "1.2.3.4"
                )

        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        # delete - ondemand service - nat
        fake_ctx = _context_for_delete(
            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'nat': {
                vcloud_network_plugin.PUBLIC_IP: "1.2.3.4"
            }
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, fake_client, vcloud_network_plugin.DELETE,
                    "1.2.3.4"
                )

        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        # delete - ondemand - not nat
        gateway.deallocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        fake_ctx = _context_for_delete(
            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'nat': {}
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                # import pdb;pdb.set_trace()
                public_nat._save_configuration(
                    gateway, fake_client, vcloud_network_plugin.DELETE,
                    "1.2.3.4"
                )
        gateway.deallocate_public_ip.assert_called_with("1.2.3.4")
        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertFalse(
            public_nat.PORT_REPLACEMENT in runtime_properties
        )
        self.assertFalse(
            vcloud_network_plugin.SSH_PORT in runtime_properties
        )
        self.assertFalse(
            vcloud_network_plugin.SSH_PUBLIC_IP in runtime_properties
        )

    def test_nat_network_operation(self):
        fake_client = self.generate_client()
        gateway = fake_client._vdc_gateway
        # used wrong operation
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat.nat_network_operation(
                fake_client, gateway, "unknow", "DNAT", "1.2.3.4",
                "2.3.4.5", "11", "11", "TCP"
            )
        # run correct operation/rule
        for operation in [
            vcloud_network_plugin.DELETE, vcloud_network_plugin.CREATE
        ]:
            for rule_type in ["SNAT", "DNAT"]:
                # cleanup properties
                fake_ctx = self.generate_relation_context_with_current_ctx()
                fake_ctx._target.instance.runtime_properties = {
                    public_nat.PORT_REPLACEMENT: {}}
                fake_ctx._source.instance.runtime_properties = {}
                # checks
                with mock.patch(
                    'vcloud_network_plugin.public_nat.ctx', fake_ctx
                ):
                    with mock.patch(
                        'vcloud_plugin_common.ctx', fake_ctx
                    ):
                        public_nat.nat_network_operation(
                            fake_client, gateway, operation, rule_type,
                            "1.2.3.4", "2.3.4.5", "11", "11", "TCP"
                        )
                if rule_type == "DNAT":
                    if operation == vcloud_network_plugin.DELETE:
                        gateway.del_nat_rule.assert_called_with(
                            'DNAT', '1.2.3.4', '11', '2.3.4.5', '11',
                            'TCP'
                        )
                    else:
                        gateway.add_nat_rule.assert_called_with(
                            'DNAT', '1.2.3.4', '11', '2.3.4.5', '11',
                            'TCP'
                        )
                else:
                    if operation == vcloud_network_plugin.DELETE:
                        gateway.del_nat_rule.assert_called_with(
                            'SNAT', '2.3.4.5', 'any', '1.2.3.4', 'any',
                            'any'
                        )
                    else:
                        gateway.add_nat_rule.assert_called_with(
                            'SNAT', '2.3.4.5', 'any', '1.2.3.4', 'any',
                            'any'
                        )
        # cleanup properties
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {}}
        fake_ctx._source.instance.runtime_properties = {}
        # save ssh port
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.nat_network_operation(
                    fake_client, gateway, vcloud_network_plugin.CREATE,
                    "DNAT", "1.2.3.4", "2.3.4.5", "43", "22", "TCP"
                )
                self.assertEqual(
                    {'port_replacement': {'1.2.3.4:43': 43}},
                    fake_ctx._target.instance.runtime_properties
                )
                self.assertEqual(
                    {'ssh_port': '43', 'ssh_public_ip': '1.2.3.4'},
                    fake_ctx._source.instance.runtime_properties
                )
                # error with type
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat.nat_network_operation(
                        fake_client, gateway, vcloud_network_plugin.CREATE,
                        "QNAT", "1.2.3.4", "2.3.4.5", "43", "22", "TCP"
                    )

    def generate_client_and_context_server(self, no_vmip=False):
        """
            for test prepare_server_operation based operations
        """
        vm_ip = '1.1.1.1' if not no_vmip else None
        fake_client = self.generate_client(vms_networks=[{
            'is_connected': True,
            'network_name': 'network_name',
            'is_primary': True,
            'ip': vm_ip
        }])
        self.set_network_routed_in_client(fake_client)
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'vdc': 'vdc_name',
                'service_type':
                    vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            }
        }
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        self.set_services_conf_result(
            fake_client._vdc_gateway,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        return fake_client, fake_ctx

    def test_prepare_server_operation(self):

        fake_client, fake_ctx = self.generate_client_and_context_server()
        # no rules for update
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat.prepare_server_operation(
                        fake_client, vcloud_network_plugin.DELETE
                    )
        # public ip equal to None in node properties
        fake_client, fake_ctx = self.generate_client_and_context_server()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT',
                'protocol': 'TCP',
                'original_port': "11",
                'translated_port': "11"
            }]
        }
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: None
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                self.assertFalse(
                    public_nat.prepare_server_operation(
                        fake_client, vcloud_network_plugin.DELETE
                    )
                )
        # we dont have connected private ip
        fake_client, fake_ctx = self.generate_client_and_context_server(
            no_vmip=True
        )
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT',
                'protocol': 'TCP',
                'original_port': "11",
                'translated_port': "11"
            }]
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                self.assertFalse(
                    public_nat.prepare_server_operation(
                        fake_client, vcloud_network_plugin.DELETE
                    )
                )
        # with some rules
        fake_client, fake_ctx = self.generate_client_and_context_server()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT',
                'protocol': 'TCP',
                'original_port': "11",
                'translated_port': "11"
            }]
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_server_operation(
                    fake_client, vcloud_network_plugin.DELETE
                )
        fake_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', '11', '1.1.1.1', '11', 'TCP'
        )
        # with default value
        fake_client, fake_ctx = self.generate_client_and_context_server()
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_server_operation(
                    fake_client, vcloud_network_plugin.DELETE
                )
        fake_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', 'any', '1.1.1.1', 'any', 'any'
        )
        # with SNAT rules
        fake_client, fake_ctx = self.generate_client_and_context_server()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{'type': 'SNAT'}, {'type': 'SNAT'}]
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_server_operation(
                    fake_client, vcloud_network_plugin.DELETE
                )
        fake_client._vdc_gateway.del_nat_rule.assert_called_with(
            'SNAT', '1.1.1.1', 'any', '192.168.1.1', 'any', 'any'
        )

    def generate_client_and_context_network(self):
        """
            for test prepare_network_operation based operations
        """
        fake_client = self.generate_client(vms_networks=[{
            'is_connected': True,
            'network_name': 'network_name',
            'is_primary': True,
            'ip': '1.1.1.1'
        }])
        self.set_network_routed_in_client(fake_client)
        gate = fake_client._vdc_gateway
        gate.get_dhcp_pools = mock.MagicMock(return_value=[])
        network = self.generate_fake_client_network(
            name="some", start_ip="127.1.1.100", end_ip="127.1.1.200"
        )
        fake_client.get_networks = mock.MagicMock(return_value=[network])
        self.set_services_conf_result(
            fake_client._vdc_gateway,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        # ctx
        fake_ctx = self.generate_relation_context_with_current_ctx()
        fake_ctx._source.instance.runtime_properties = {
            vcloud_network_plugin.network.VCLOUD_NETWORK_NAME: "some"
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'org': 'some_org',
                'vdc': 'vdc_name',
                'service_type':
                    vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            }
        }
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        return fake_client, fake_ctx

    def test_prepare_network_operation(self):
        # no rules
        fake_client, fake_ctx = self.generate_client_and_context_network()
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat.prepare_network_operation(
                        fake_client, vcloud_network_plugin.DELETE
                    )
        # public ip equal to None in node properties
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: None
        }
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT',

            }]
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                self.assertFalse(
                    public_nat.prepare_network_operation(
                        fake_client, vcloud_network_plugin.DELETE
                    )
                )
        # rules with default values
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        with mock.patch(
            'vcloud_network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_network_operation(
                    fake_client, vcloud_network_plugin.DELETE
                )
        fake_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', 'any', '127.1.1.100 - 127.1.1.200',
            'any', 'any'
        )

    def test_creation_validation(self):
        fake_client = self.generate_client()
        # no nat
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # no gateway
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'nat': {
                    'some_field': 'something'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # wrong ip
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    vcloud_network_plugin.PUBLIC_IP: 'any'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # no free ip
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # no rules
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    vcloud_network_plugin.PUBLIC_IP: '10.12.2.1'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # wrong protocol
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    vcloud_network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "some"
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # wrong original_port
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    vcloud_network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "TCP",
                    'original_port': 'some'
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)

        # wrong original_port
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    vcloud_network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "TCP",
                    'original_port': 11,
                    'translated_port': 'some'
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx, vca_client=None)
        # fine
        fake_ctx = self.generate_node_context_with_current_ctx(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type':
                        vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    vcloud_network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "TCP",
                    'original_port': 11,
                    'translated_port': 12
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.creation_validation(ctx=fake_ctx, vca_client=None)

    def _server_disconnect_to_nat_noexternal(self):
        fake_client, fake_ctx = self.generate_client_and_context_server()
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        fake_ctx._source.node.properties = {
            'vcloud_config':
            {
                'edge_gateway': 'gateway',
                'vdc': 'vdc'
            }
        }
        fake_ctx._source.instance.runtime_properties = {
            'gateway_lock': False,
            'vcloud_vapp_name': 'vapp'
        }
        return fake_client, fake_ctx

    def test_server_disconnect_from_nat(self):
        # successful
        fake_client, fake_ctx = self._server_disconnect_to_nat_noexternal()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.server_disconnect_from_nat(ctx=fake_ctx)
        fake_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', 'any', '1.1.1.1', 'any', 'any'
        )
        # check retry
        fake_client, fake_ctx = self._server_disconnect_to_nat_noexternal()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.prepere_gatway_busy_retry(fake_client, fake_ctx)
            public_nat.server_disconnect_from_nat(ctx=fake_ctx)
            self.check_retry_realy_called(fake_ctx)

    def _server_connect_to_nat_noexternal(self):
        fake_client, fake_ctx = self.generate_client_and_context_server()
        fake_ctx._target.instance.runtime_properties = {
            vcloud_network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        fake_ctx._source.instance.runtime_properties = {
            'gateway_lock': False,
            'vcloud_vapp_name': 'vapp'
        }
        fake_ctx._source.node.properties = {
            'vcloud_config':
            {
                'edge_gateway': 'gateway',
                'vdc': 'vdc'
            }
        }
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }

        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(
            return_value=['10.18.1.1']
        )
        return fake_client, fake_ctx

    def test_server_connect_to_nat(self):
        fake_client, fake_ctx = self._server_connect_to_nat_noexternal()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.server_connect_to_nat(ctx=fake_ctx)
        fake_client._vdc_gateway.add_nat_rule.assert_called_with(
            'DNAT', '10.18.1.1', 'any', '1.1.1.1', 'any', 'any'
        )
        fake_client, fake_ctx = self._server_connect_to_nat_noexternal()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.prepere_gatway_busy_retry(fake_client, fake_ctx)
            public_nat.server_connect_to_nat(ctx=fake_ctx)
            self.check_retry_realy_called(fake_ctx)

    def _net_disconnect_from_nat_noexternal(self):
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        fake_ctx._source.node.properties = {
            'vcloud_config':
            {
                'edge_gateway': 'gateway',
                'vdc': 'vdc'
            }
        }
        return fake_client, fake_ctx

    def test_net_disconnect_from_nat(self):
        # use external
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'use_external_resource': True
        }
        fake_ctx._source.node.properties = {
            'vcloud_config':
            {
                'edge_gateway': 'gateway',
                'vdc': 'vdc'
            }
        }
        fake_ctx._source.instance.runtime_properties = {
            'gateway_lock': False,
            'vcloud_vapp_name': 'vapp'
        }

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.net_disconnect_from_nat(ctx=fake_ctx)
        # no external
        fake_client, fake_ctx = self._net_disconnect_from_nat_noexternal()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.net_disconnect_from_nat(ctx=fake_ctx)
        fake_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', 'any', '127.1.1.100 - 127.1.1.200',
            'any', 'any'
        )
        # retry check
        fake_client, fake_ctx = self._net_disconnect_from_nat_noexternal()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.prepere_gatway_busy_retry(fake_client, fake_ctx)
            public_nat.net_disconnect_from_nat(ctx=fake_ctx)
            self.check_retry_realy_called(fake_ctx)

    def test_net_connect_to_nat(self):
        # use external
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'use_external_resource': True
        }
        fake_ctx._source.node.properties = {
            'vcloud_config':
            {
                'edge_gateway': 'gateway',
                'vdc': 'vdc'
            }
        }

        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.net_connect_to_nat(ctx=fake_ctx, vca_client=None)
        # no external
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        fake_ctx._source.node.properties = {
            'vcloud_config':
            {
                'edge_gateway': 'gateway',
                'vdc': 'vdc'
            }
        }
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1'
        ])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.net_connect_to_nat(ctx=fake_ctx, vca_client=None)
        fake_client._vdc_gateway.add_nat_rule.assert_called_with(
            'DNAT', '10.18.1.1', 'any', '127.1.1.100 - 127.1.1.200',
            'any', 'any'
        )
        # retry check
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            self.prepere_gatway_busy_retry(fake_client, fake_ctx)
            public_nat.net_connect_to_nat(ctx=fake_ctx, vca_client=None)
            self.check_retry_realy_called(fake_ctx)

    def test_net_connect_to_nat_preconfigure(self):
        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.net_connect_to_nat_preconfigure(ctx=fake_ctx,
                                                           vca_client=None)

        fake_client, fake_ctx = self.generate_client_and_context_network()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'SNAT'
            }]
        }
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.net_connect_to_nat_preconfigure(ctx=fake_ctx,
                                                       vca_client=None)
        # empty rules
        fake_ctx._target.node.properties.update({'rules': []})
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.net_connect_to_nat_preconfigure(ctx=fake_ctx,
                                                           vca_client=None)


if __name__ == '__main__':
    unittest.main()
