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

from tests.unittests import test_mock_base
from network_plugin import floatingip
from cloudify import exceptions as cfy_exc
import network_plugin
import vcloud_plugin_common


class NetworkPluginFloatingIpMockTestCase(test_mock_base.TestBase):

    def test_add_nat_rule_snat(self):
        fake_ctx = self.generate_node_context()
        with mock.patch('network_plugin.floatingip.ctx', fake_ctx):
            gateway = mock.Mock()
            gateway._add_nat_rule = mock.MagicMock(return_value=None)
            floatingip._add_nat_rule(
                gateway, 'SNAT', 'internal', 'external'
            )
            gateway.add_nat_rule.assert_called_with(
                'SNAT', 'internal', 'any', 'external', 'any', 'any'
            )

    def test_add_nat_rule_dnat(self):
        fake_ctx = self.generate_node_context()
        with mock.patch('network_plugin.floatingip.ctx', fake_ctx):
            gateway = mock.Mock()
            gateway._add_nat_rule = mock.MagicMock(return_value=None)
            floatingip._add_nat_rule(
                gateway, 'DNAT', 'internal', 'external'
            )
            gateway.add_nat_rule.assert_called_with(
                'DNAT', 'internal', 'any', 'external', 'any', 'any'
            )

    def test_del_nat_rule_snat(self):
        fake_ctx = self.generate_node_context()
        with mock.patch('network_plugin.floatingip.ctx', fake_ctx):
            gateway = mock.Mock()
            gateway.del_nat_rule = mock.MagicMock(return_value=None)
            floatingip._del_nat_rule(
                gateway, 'SNAT', 'internal', 'external'
            )
            gateway.del_nat_rule.assert_called_with(
                'SNAT', 'internal', 'any', 'external', 'any', 'any'
            )

    def test_del_nat_rule_dnat(self):
        fake_ctx = self.generate_node_context()
        with mock.patch('network_plugin.floatingip.ctx', fake_ctx):
            gateway = mock.Mock()
            gateway.del_nat_rule = mock.MagicMock(return_value=None)
            floatingip._del_nat_rule(
                gateway, 'DNAT', 'internal', 'external'
            )
            gateway.del_nat_rule.assert_called_with(
                'DNAT', 'internal', 'any', 'external', 'any', 'any'
            )

    def test_creation_validation(self):
        fake_client = self.generate_client()
        # no floating_ip
        fake_ctx = self.generate_node_context(
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
                floatingip.creation_validation(ctx=fake_ctx)
        # no edge gateway
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'floatingip': {
                    'some_field': 'some value'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                floatingip.creation_validation(ctx=fake_ctx)
        # with edge gateway, but wrong ip
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'floatingip': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: 'some'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                floatingip.creation_validation(ctx=fake_ctx)
        # with edge gateway, ip from pool
        fake_ctx = self.generate_node_context(properties={
            'vcloud_config': {
                'vdc': 'vdc_name'
            },
            'floatingip': {
                'edge_gateway': 'gateway',
                'service_type': vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
            }
        })
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(
            return_value=['10.18.1.1']
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            floatingip.creation_validation(ctx=fake_ctx)
        # with some free ip
        fake_ctx = self.generate_node_context(properties={
            'vcloud_config': {
                'vdc': 'vdc_name'
            },
            'floatingip': {
                'edge_gateway': 'gateway',
                network_plugin.PUBLIC_IP: '10.10.1.2',
                'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            }
        })
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.1.1.1', '10.1.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.1.1.1', 'any', '123.1.1.1', '11', 'TCP'
        )
        fake_client.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            floatingip.creation_validation(ctx=fake_ctx)

    def generate_client_and_context_floating_ip(
        self, service_type=vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
    ):
        # client
        vms_networks = [{
            'is_connected': True,
            'network_name': 'network_name',
            'is_primary': True,
            'ip': '1.1.1.1'
        }]
        fake_client = self.generate_client(vms_networks=vms_networks)
        self.set_network_routed_in_client(fake_client)
        self.set_services_conf_result(
            fake_client._vdc_gateway,
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        # ctx
        fake_ctx = self.generate_relation_context()
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'service_type': service_type,
                'org': 'some_org',
                'vdc': 'some_vdc',
            }
        }
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {}
        return fake_client, fake_ctx

    def test_floatingip_operation_delete(self):
        """
            check for floating_ip operations/delete
        """
        # no public_ip delete
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip()
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        with mock.patch(
            'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                floatingip._floatingip_operation(
                    network_plugin.DELETE, fake_client, fake_ctx
                )
        # busy in save with ip in node_properties
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip()
        self.set_services_conf_result(
            fake_client._vdc_gateway, None
        )
        self.set_gateway_busy(fake_client._vdc_gateway)
        self.prepare_retry(fake_ctx)
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway',
                network_plugin.PUBLIC_IP: '10.10.1.2'
            }
        }
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                self.assertFalse(floatingip._floatingip_operation(
                    network_plugin.DELETE, fake_client, fake_ctx
                ))
        # busy in save with ip in runtime_properties
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip()
        self.set_services_conf_result(
            fake_client._vdc_gateway, None
        )
        self.set_gateway_busy(fake_client._vdc_gateway)
        self.prepare_retry(fake_ctx)
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '10.10.1.2'
        }
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                self.assertFalse(floatingip._floatingip_operation(
                    network_plugin.DELETE, fake_client, fake_ctx
                ))
        # unknow operation
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip()
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway',
                network_plugin.PUBLIC_IP: '10.10.1.2'
            }
        }
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    floatingip._floatingip_operation(
                        "unknow", fake_client, fake_ctx
                    )
        # delete to end, ondemand
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip()
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '10.10.1.2'
        }
        fake_client._vdc_gateway.deallocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                floatingip._floatingip_operation(
                    network_plugin.DELETE, fake_client, fake_ctx
                )
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertFalse(
            network_plugin.PUBLIC_IP in runtime_properties
        )
        # delete to end, subscription
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip(
            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '10.10.1.2'
        }
        fake_client._vdc_gateway.deallocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                floatingip._floatingip_operation(
                    network_plugin.DELETE, fake_client, fake_ctx
                )
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertFalse(
            network_plugin.PUBLIC_IP in runtime_properties
        )

    def test_disconnect_floatingip(self):
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip()
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '10.10.1.2'
        }
        fake_client._vdc_gateway.deallocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            floatingip.disconnect_floatingip(
                ctx=fake_ctx
            )
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertFalse(
            network_plugin.PUBLIC_IP in runtime_properties
        )

    def test_connect_floatingip(self):
        """
            check connect_floatingip with explicitly defined ip
        """
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip(
            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway',
                network_plugin.PUBLIC_IP: '10.10.2.3'
            }
        }
        fake_ctx._target.instance.runtime_properties = {}
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.10.2.3'
        ])
        fake_client._vdc_gateway.get_nat_rules = mock.MagicMock(
            return_value=[]
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            floatingip.connect_floatingip(
                ctx=fake_ctx
            )
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertTrue(
            network_plugin.PUBLIC_IP in runtime_properties
        )
        self.assertEqual(
            runtime_properties.get(network_plugin.PUBLIC_IP),
            '10.10.2.3'
        )

    def test_floatingip_operation_create(self):
        """
            check for floating_ip operations/create
        """
        # create to end
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip(
            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway'
            }
        }
        fake_ctx._target.instance.runtime_properties = {}
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1'
        ])
        fake_client._vdc_gateway.get_nat_rules = mock.MagicMock(
            return_value=[]
        )
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                floatingip._floatingip_operation(
                    network_plugin.CREATE, fake_client, fake_ctx
                )
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertTrue(
            network_plugin.PUBLIC_IP in runtime_properties
        )
        self.assertEqual(
            runtime_properties.get(network_plugin.PUBLIC_IP),
            '10.18.1.1'
        )
        # with already explicitly defined ip
        fake_client, fake_ctx = self.generate_client_and_context_floating_ip(
            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'floatingip': {
                'edge_gateway': 'gateway',
                network_plugin.PUBLIC_IP: '10.10.2.3'
            }
        }
        fake_ctx._target.instance.runtime_properties = {}
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.10.2.3'
        ])
        fake_client._vdc_gateway.get_nat_rules = mock.MagicMock(
            return_value=[]
        )
        with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'network_plugin.floatingip.ctx', fake_ctx
            ):
                floatingip._floatingip_operation(
                    network_plugin.CREATE, fake_client, fake_ctx
                )
        runtime_properties = fake_ctx._target.instance.runtime_properties
        self.assertTrue(
            network_plugin.PUBLIC_IP in runtime_properties
        )
        self.assertEqual(
            runtime_properties.get(network_plugin.PUBLIC_IP),
            '10.10.2.3'
        )

if __name__ == '__main__':
    unittest.main()
