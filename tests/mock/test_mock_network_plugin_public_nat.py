import mock
import unittest

import test_mock_base
from network_plugin import public_nat


class NetworkPluginPublicNatMockTestCase(test_mock_base.TestBase):

    def test_is_rule_exsists(self):
        rule = mock.Mock()
        rule.get_OriginalIp = mock.MagicMock(return_value="external")
        rule.get_OriginalPort = mock.MagicMock(return_value="22")
        rule.get_TranslatedIp = mock.MagicMock(return_value="internal")
        rule.get_TranslatedPort = mock.MagicMock(return_value="11")
        rule.get_Protocol = mock.MagicMock(return_value="tcp")
        rule_inlist = mock.Mock()
        rule_inlist.get_RuleType = mock.MagicMock(return_value="snat")
        rule_inlist.get_GatewayNatRule = mock.MagicMock(return_value=rule)
        # exist
        self.assertTrue(
            public_nat._is_rule_exsists(
                [rule_inlist], 'SNAT', 'external', '22', 'internal',
                '11', 'TCP')
        )
        # not exist
        self.assertFalse(
            public_nat._is_rule_exsists(
                [rule_inlist], 'SNAT', 'external', '22', 'internal',
                '11', 'UDP')
        )

    def test_get_original_port_for_delete(self):
        # no replacement
        fake_ctx = self.generate_context(properties={})
        fake_ctx._source = mock.Mock()
        fake_ctx._target = mock.Mock()
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.1", "11"),
                "11"
            )
        # replacement for other
        fake_ctx = self.generate_context(properties={})
        fake_ctx._source = mock.Mock()
        fake_ctx._target = mock.Mock()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {
                ("10.1.1.2", "11"): '12'
            }
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.1", "11"),
                "11"
            )
        # replacement for other
        fake_ctx = self.generate_context(properties={})
        fake_ctx._source = mock.Mock()
        fake_ctx._target = mock.Mock()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {
                ("10.1.1.2", "11"): '12'
            }
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.2", "11"),
                "12"
            )


if __name__ == '__main__':
    unittest.main()
