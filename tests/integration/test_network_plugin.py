import mock
import unittest
from cloudify.mocks import MockCloudifyContext
from network_plugin import floatingip, network, security_group, public_nat
from server_plugin.server import VCLOUD_VAPP_NAME
from network_plugin import isExternalIpAssigned
from cloudify import exceptions as cfy_exc
from tests.integration import TestCase, IntegrationTestConfig, VcloudTestConfig
# for skipping test add this before test function:
# @unittest.skip("demonstrating skipping")

@unittest.skip("demonstrating skipping")
class FloatingIPOperationsTestCase(TestCase):
    def setUp(self):
        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={},
            target=MockCloudifyContext(node_id="target",
                                       properties={'floatingip': {}}),
            source=MockCloudifyContext(node_id="source",
                                       properties={'vcloud_config': {}},
                                       runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['test_vm']}))
        ctx_patch1 = mock.patch('network_plugin.floatingip.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)
        super(FloatingIPOperationsTestCase, self).setUp()

    def tearDown(self):
        super(FloatingIPOperationsTestCase, self).tearDown()

    def test_floating_ip_create_delete_with_explicit_ip(self):
        self.ctx.target.node.properties['floatingip'].update(IntegrationTestConfig().get()['floatingip'])
        public_ip = self.ctx.target.node.properties['floatingip']['public_ip']
        check_external = lambda: isExternalIpAssigned(public_ip, self._get_gateway())
        self.assertFalse(check_external())
        floatingip.connect_floatingip()
        self.assertTrue(check_external())
        self.assertRaises(cfy_exc.NonRecoverableError,
                          floatingip.connect_floatingip)
        floatingip.disconnect_floatingip()
        self.assertFalse(check_external())

    def test_floating_ip_create_delete_with_autoget_ip(self):
        self.ctx.target.node.properties['floatingip'].update(IntegrationTestConfig().get()['floatingip'])
        del self.ctx.target.node.properties['floatingip']['public_ip']

        floatingip.connect_floatingip()
        public_ip = self.ctx.target.instance.runtime_properties['public_ip']
        check_external = lambda: isExternalIpAssigned(public_ip, self._get_gateway())
        self.assertTrue(public_ip)
        self.assertTrue(check_external())
        self.assertRaises(cfy_exc.NonRecoverableError,
                          floatingip.connect_floatingip)
        floatingip.disconnect_floatingip()
        self.assertFalse(check_external())

    def _get_gateway(self):
        return self.vca_client.get_gateway(VcloudTestConfig().get()["vdc"],
                                           self.ctx.target.node.properties['floatingip']['edge_gateway'])

@unittest.skip("demonstrating skipping")
class OrgNetworkOperationsTestCase(TestCase):
    def setUp(self):

        self.net_name = "test_network"
        self.ctx = MockCloudifyContext(
            node_id=self.net_name,
            node_name=self.net_name,
            properties={"resource_id": self.net_name,
                        "network": IntegrationTestConfig().get()['network'],
                        "dhcp": IntegrationTestConfig().get()['dhcp'],
                        "vcloud_config": VcloudTestConfig().get(),
                        "use_external_resource": False})
        self.vdc_name = VcloudTestConfig().get()["vdc"]
        ctx_patch1 = mock.patch('network_plugin.network.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)
        super(OrgNetworkOperationsTestCase, self).setUp()

    def get_pools(self):
        gateway = self.vca_client.get_gateways(self.vdc_name)[0]
        if not gateway:
            raise cfy_exc.NonRecoverableError("Gateway not found")
        gatewayConfiguration = gateway.me.get_Configuration()
        edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
        dhcpService = filter(lambda service: service.__class__.__name__ == "GatewayDhcpServiceType",
                             edgeGatewayServiceConfiguration.get_NetworkService())[0]
        return dhcpService.get_Pool()

    def tearDown(self):
        super(OrgNetworkOperationsTestCase, self).tearDown()

    def test_orgnetwork_create_delete(self):
        self.assertNotIn(self.net_name,
                         network._get_network_list(self.vca_client, self.vdc_name))
        start_pools = len(self.get_pools())
        network.create()
        self.assertIn(self.net_name,
                      network._get_network_list(self.vca_client, self.vdc_name))
        self.assertEqual(start_pools + 1, len(self.get_pools()))
        network.delete()
        self.assertNotIn(self.net_name,
                         network._get_network_list(self.vca_client, self.vdc_name))
        self.assertEqual(start_pools, len(self.get_pools()))

@unittest.skip("demonstrating skipping")
class FirewallRulesOperationsTestCase(TestCase):
    def setUp(self):

        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={},
            target=MockCloudifyContext(node_id="target",
                                       properties=IntegrationTestConfig().get()['security_group']),
            source=MockCloudifyContext(node_id="source",
                                       properties={'vcloud_config': VcloudTestConfig().get()},
                                       runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['test_vm']}))
        ctx_patch1 = mock.patch('network_plugin.security_group.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)
        self.vdc_name = VcloudTestConfig().get()["vdc"]
        super(FirewallRulesOperationsTestCase, self).setUp()

    def tearDown(self):
        super(FirewallRulesOperationsTestCase, self).tearDown()

    def test_firewall_rules_create_delete(self):
        rules = len(self.get_rules())
        security_group.create()
        self.assertEqual(rules + 1, len(self.get_rules()))
        security_group.delete()
        self.assertEqual(rules, len(self.get_rules()))

    def get_rules(self):
        gateway = self.vca_client.get_gateways(self.vdc_name)[0]
        if not gateway:
            raise cfy_exc.NonRecoverableError("Gateway not found")
        gatewayConfiguration = gateway.me.get_Configuration()
        edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
        firewallService = filter(lambda service: service.__class__.__name__ == "FirewallServiceType",
                                 edgeGatewayServiceConfiguration.get_NetworkService())[0]
        return firewallService.get_FirewallRule()


class PublicNatOperationsTestCase(TestCase):
    def setUp(self):
        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={},
            target=MockCloudifyContext(node_id="target",
                                       properties={}),
            source=MockCloudifyContext(node_id="source",
                                       properties={'nat': IntegrationTestConfig().get()['public_nat']['nat'],
                                                   "rules": {}},
                                       runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['test_vm']}))
        ctx_patch1 = mock.patch('network_plugin.public_nat.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)
        super(PublicNatOperationsTestCase, self).setUp()

    def tearDown(self):
        super(PublicNatOperationsTestCase, self).tearDown()

    @unittest.skip("demonstrating skipping")
    def test_public_nat_connected_to_net(self):
        self.ctx.source.node.properties['rules'] = IntegrationTestConfig().get()['public_nat']['rules_net']
        self.ctx.target.node.properties['resource_id'] = IntegrationTestConfig().get()['public_nat']['network_name']
        public_nat.connect_nat_to_network()
        public_nat.disconnect_nat_from_network()

    def test_public_nat_connected_to_vm(self):
        self.ctx.source.node.properties['rules'] = IntegrationTestConfig().get()['public_nat']['rules_port']
        self.ctx.target.node.properties['port'] = IntegrationTestConfig().get()['public_nat']['port']
        public_nat.connect_nat_to_vm()
        public_nat.disconnect_nat_from_vm()


if __name__ == '__main__':
    unittest.main()
