import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
import network_plugin
import vcloud_plugin_common


class NetworkPluginMockTestCase(test_mock_base.TestBase):

    def test_get_vm_ip(self):
        fake_client = self.generate_client(vms_networks=[])
        fake_ctx = self.generate_context()
        fake_ctx._source = mock.Mock()
        fake_ctx._source.node = mock.Mock()
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'edge_gateway': 'some_edge_gateway',
                'vdc': 'vdc_name'
            }
        }
        fake_ctx._target = mock.Mock()
        fake_ctx._target.node = mock.Mock()
        # empty connections/no connection name
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                )

    def test_collectAssignedIps(self):
        # empty gateway
        self.assertEqual(
            network_plugin.collectAssignedIps(None),
            set([])
        )
        # snat
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        self.assertEqual(
            network_plugin.collectAssignedIps(gateway),
            set([network_plugin.AssignedIPs(
                external='internal', internal='external'
            )])
        )
        # dnat
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'DNAT', 'external', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        self.assertEqual(
            network_plugin.collectAssignedIps(gateway),
            set([network_plugin.AssignedIPs(
                external='external', internal='internal'
            )])
        )

    def test_getFreeIP(self):
        # exist free ip
        gateway = mock.Mock()
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

    def test_get_public_ip(self):
        gateway = mock.Mock()
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.18.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.18.1.1', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        fake_ctx = self.generate_context()
        # for subscription we dont use client
        self.assertEqual(
            network_plugin.get_public_ip(
                None, gateway,
                vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE, fake_ctx
            ),
            '10.18.1.2'
        )
        #TODO add ondemand test

if __name__ == '__main__':
    unittest.main()
