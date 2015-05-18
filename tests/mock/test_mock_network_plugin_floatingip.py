import mock
import unittest

import test_mock_base
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
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'floatingip': {
                    'edge_gateway': 'gateway',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                }
            }
        )
        fake_client._vdc_gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1'
        ])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            floatingip.creation_validation(ctx=fake_ctx)
        # with some free ip
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'floatingip': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: '10.10.1.2',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                }
            }
        )
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

if __name__ == '__main__':
    unittest.main()
