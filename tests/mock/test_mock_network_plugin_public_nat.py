import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
from network_plugin import public_nat
import network_plugin
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
                [rule_inlist], 'SNAT', 'external', '22', 'internal',
                '11', 'UDP')
        )

    def test_get_original_port_for_delete(self):
        # no replacement
        fake_ctx = self.generate_context()
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
        fake_ctx = self.generate_context()
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
        fake_ctx = self.generate_context()
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

    def test_get_original_port_for_create(self):
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        # exeption about same port
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._get_original_port_for_create(
                gateway, 'SNAT', 'external', 'any', 'internal', '11', 'TCP'
            )
        # everythiong fine with different port
        self.assertEqual(
            public_nat._get_original_port_for_create(
                gateway, 'SNAT', 'external', 'any', 'internal', '12', 'TCP'
            ),
            'any'
        )
        # relink some port to other
        # port have not used yet
        self.assertEqual(
            public_nat._get_original_port_for_create(
                gateway, 'SNAT', 'external', 10, 'internal', '12', 'TCP'
            ),
            10
        )

    def test_get_original_port_for_create_with_ctx(self):
        # with replace, but without replace table - up port +1
        fake_ctx = self.generate_context()
        fake_ctx._source = mock.Mock()
        fake_ctx._target = mock.Mock()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {}
        }
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 10, 'internal', 11, 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
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
                    public_nat.PORT_REPLACEMENT:  {
                        ('external', '10'): 11
                    }
                }
            )
        # same but without replacement at all
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
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
                        ('external', '10'): 11
                    }
                }
            )
        # we dont have enought ports
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', public_nat.MAX_PORT_NUMBER,
            'internal', 11, 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external',
                    public_nat.MAX_PORT_NUMBER, 'internal', '11', 'TCP'
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
        fake_ctx = self.generate_context()
        fake_ctx._source = mock.Mock()
        fake_ctx._target = mock.Mock()
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        gateway = mock.Mock()
        vca_client = mock.Mock()
        # exist some ip for delete
        self.assertEqual(
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, network_plugin.DELETE
            ),
            '192.168.1.1'
        )
        # no ip for delete
        fake_ctx._target.instance.runtime_properties = {}
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, network_plugin.DELETE
            )
        # unknow operation
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, 'unknow operation'
            )
        # exist some public ip
        fake_ctx._target.node.properties = {
            'nat': {
                network_plugin.PUBLIC_IP: '192.168.1.1'
            }
        }
        self.assertEqual(
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, network_plugin.CREATE
            ),
            '192.168.1.1'
        )


if __name__ == '__main__':
    unittest.main()
