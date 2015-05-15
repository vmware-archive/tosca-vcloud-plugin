import mock
import unittest

import test_mock_base
from network_plugin import floatingip


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

if __name__ == '__main__':
    unittest.main()
