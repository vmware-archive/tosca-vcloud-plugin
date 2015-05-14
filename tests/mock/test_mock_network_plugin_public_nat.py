import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
from network_plugin import public_nat
import network_plugin
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
        # no public ip yet
        fake_ctx._target.node.properties = {
            'nat': {}
        }
        fake_ctx._source = mock.Mock()
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
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                self.assertEqual(
                    public_nat._obtain_public_ip(
                        vca_client, fake_ctx, gateway,
                        network_plugin.CREATE
                    ),
                    '10.18.1.2'
                )

    def test_get_network_ip_range(self):
        # dont have ip range for this network
        vca_client = self.generate_client()
        self.assertEqual(
            public_nat._get_network_ip_range(
                vca_client, "some_org", "some_network"
            ),
            None
        )
        vca_client.get_networks.assert_called_with("some_org")
        # different network
        network = self.gen_vca_client_network(
            name="some", start_ip="127.1.1.1", end_ip="127.1.1.255"
        )
        vca_client.get_networks = mock.MagicMock(return_value=[network])
        self.assertEqual(
            public_nat._get_network_ip_range(
                vca_client, "some_org", "some_network"
            ),
            None
        )
        # correct network name
        vca_client.get_networks = mock.MagicMock(return_value=[network])
        self.assertEqual(
            public_nat._get_network_ip_range(
                vca_client, "some_org", "some"
            ),
            (IP('127.1.1.1'), IP('127.1.1.255'))
        )

    def test_create_ip_range(self):
        # context
        fake_ctx = self.generate_context()
        fake_ctx._source = mock.Mock()
        fake_ctx._source.instance.runtime_properties = {
            network_plugin.network.VCLOUD_NETWORK_NAME: "some"
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'org': 'some_org'
            }
        }
        fake_ctx._target = mock.Mock()
        fake_ctx._target.instance.runtime_properties = {}
        # gateway
        gate = mock.Mock()
        gate.get_dhcp_pools = mock.MagicMock(return_value=[])
        # vca client
        vca_client = self.generate_client()
        network = self.gen_vca_client_network(
            name="some", start_ip="127.1.1.100", end_ip="127.1.1.200"
        )
        vca_client.get_networks = mock.MagicMock(return_value=[network])
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                # empty gateway dhcp pool
                # vca pool: 127.1.1.100..127.1.1.200
                self.assertEqual(
                    public_nat._create_ip_range(vca_client, gate),
                    '127.1.1.100 - 127.1.1.200'
                )
                vca_client.get_networks.assert_called_with("some_org")
                # network from gate
                gate.get_dhcp_pools = mock.MagicMock(return_value=[
                    self.genarate_pool(
                        "some", '127.1.1.1', '127.1.1.255'
                    )
                ])
                self.assertEqual(
                    public_nat._create_ip_range(vca_client, gate),
                    '127.1.1.1 - 127.1.1.255'
                )
                # network not exist
                network = self.gen_vca_client_network(
                    name="other", start_ip="127.1.1.100",
                    end_ip="127.1.1.200"
                )
                vca_client.get_networks = mock.MagicMock(
                    return_value=[network]
                )
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat._create_ip_range(vca_client, gate)

if __name__ == '__main__':
    unittest.main()
