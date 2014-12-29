import mock
import unittest
from cloudify.mocks import MockCloudifyContext, MockNodeInstanceContext
from tests.integration import TestCase
from network_plugin import floatingip
from network_plugin import network
from network_plugin.floatingip import VCLOUD_VAPP_NAME


# for skipping test add this before test function:
# @unittest.skip("demonstrating skipping")

class NatRulesOperationsTestCase(TestCase):

    def setUp(self):
        super(NatRulesOperationsTestCase, self).setUp()

        name = "testnode"
        self.public_ip = '23.92.245.236'
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={'floatingip': {'public_ip': self.public_ip,
                                       'gateway': 'M966854774-4471'}})

        network_relationship = mock.Mock()
        network_relationship.target = mock.Mock()
        network_relationship.target.instance = MockNodeInstanceContext(
            runtime_properties={VCLOUD_VAPP_NAME: 'ilyashenko'})
        self.ctx.instance.relationships = [network_relationship]

        ctx_patch1 = mock.patch('network_plugin.floatingip.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        super(NatRulesOperationsTestCase, self).tearDown()

    def test_nat_rules_create_delete(self):
        self.assertNotIn(self.public_ip, self._collectExternalIps())
        floatingip.connect_floatingip()
        self.assertIn(self.public_ip, self._collectExternalIps())
        floatingip.disconnect_floatingip()
        self.assertNotIn(self.public_ip, self._collectExternalIps())

    def _collectExternalIps(self):
        ips = []
        gateway = self.vcd_client.get_gateway(
            self.ctx.node.properties['floatingip']['gateway'])
        if gateway:
            for natRule in gateway.get_nat_rules():
                rule = natRule.get_GatewayNatRule()
                rule_type = natRule.get_RuleType()
                if rule_type == "DNAT":
                    ips.append(rule.get_OriginalIp())
                else:
                    ips.append(rule.get_TranslatedIp())
        return ips


class OrgNetworkOperationsTestCase(TestCase):

    def setUp(self):
        super(OrgNetworkOperationsTestCase, self).setUp()

        self.net_name = "test_network"
        self.ctx = MockCloudifyContext(
            node_id=self.net_name,
            node_name=self.net_name,
            properties={"resource_id": self.net_name,
                        "network":
                        {"start_address": "192.168.0.100",
                         "end_address": "192.168.0.199",
                         "gateway_ip": "192.168.0.1",
                         "netmask": "255.255.255.0",
                         "dns": "10.147.115.1",
                         "dns_duffix": "example.com"},
                        "use_external_resource": False})

        ctx_patch1 = mock.patch('network_plugin.network.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        super(OrgNetworkOperationsTestCase, self).tearDown()

    def test_orgnetwork_create_delete(self):
        self.assertNotIn(self.net_name,
                         network._get_network_list(self.vcd_client))
        network.create()
        self.assertIn(self.net_name,
                      network._get_network_list(self.vcd_client))
        network.delete()
        self.assertNotIn(self.net_name,
                         network._get_network_list(self.vcd_client))


if __name__ == '__main__':
    unittest.main()
