import mock
import unittest
from cloudify.mocks import MockCloudifyContext, MockNodeInstanceContext
from network_plugin import floatingip, network, security_group
from server_plugin.server import VCLOUD_VAPP_NAME
from network_plugin import isExternalIpAssigned
from cloudify import exceptions as cfy_exc
from tests.integration import TestCase, IntegrationTestConfig

# for skipping test add this before test function:
# @unittest.skip("demonstrating skipping")


@unittest.skip("demonstrating skipping")
class NatRulesOperationsTestCase(TestCase):
    def setUp(self):
        super(NatRulesOperationsTestCase, self).setUp()

        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={'floatingip': {}})

        network_relationship = mock.Mock()
        network_relationship.target = mock.Mock()
        network_relationship.target.instance = MockNodeInstanceContext(
            runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['test_vm']})
        self.ctx.instance.relationships = [network_relationship]

        ctx_patch1 = mock.patch('network_plugin.floatingip.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        super(NatRulesOperationsTestCase, self).tearDown()

    def test_nat_rules_create_delete_with_explicit_ip(self):
        self.ctx.node.properties['floatingip'].update(IntegrationTestConfig().get()['floatingip'])
        public_ip = self.ctx.node.properties['floatingip']['public_ip']
        check_external = lambda: isExternalIpAssigned(public_ip, self._get_gateway())
        self.assertFalse(check_external())
        floatingip.connect_floatingip()
        self.assertTrue(check_external())
        self.assertRaises(cfy_exc.NonRecoverableError,
                          floatingip.connect_floatingip)
        floatingip.disconnect_floatingip()
        self.assertFalse(check_external())

    def test_nat_rules_create_delete_with_autoget_ip(self):
        self.ctx.node.properties['floatingip'].update(IntegrationTestConfig().get()['floatingip'])
        del self.ctx.node.properties['floatingip']['public_ip']

        floatingip.connect_floatingip()
        public_ip = self.ctx.instance.runtime_properties['public_ip']
        check_external = lambda: isExternalIpAssigned(public_ip, self._get_gateway())
        self.assertTrue(public_ip)
        self.assertTrue(check_external())
        self.assertRaises(cfy_exc.NonRecoverableError,
                          floatingip.connect_floatingip)
        floatingip.disconnect_floatingip()
        self.assertFalse(check_external())

    def _get_gateway(self):
        return self.vcd_client.get_gateway(
            self.ctx.node.properties['floatingip']['gateway'])


@unittest.skip("demonstrating skipping")
class OrgNetworkOperationsTestCase(TestCase):
    def setUp(self):
        super(OrgNetworkOperationsTestCase, self).setUp()

        self.net_name = "test_network"
        self.ctx = MockCloudifyContext(
            node_id=self.net_name,
            node_name=self.net_name,
            properties={"resource_id": self.net_name,
                        "network": IntegrationTestConfig().get()['network'],
                        "dhcp": IntegrationTestConfig().get()['dhcp'],
                        "use_external_resource": False})

        ctx_patch1 = mock.patch('network_plugin.network.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def get_pools(self):
        gateway = self.vcd_client.get_gateways()[0]
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
                         network._get_network_list(self.vcd_client))
        start_pools = len(self.get_pools())
        network.create()
        self.assertIn(self.net_name,
                      network._get_network_list(self.vcd_client))
        self.assertEqual(start_pools + 1, len(self.get_pools()))
        network.delete()
        self.assertNotIn(self.net_name,
                         network._get_network_list(self.vcd_client))
        self.assertEqual(start_pools, len(self.get_pools()))


class FirewallRulesOperationsTestCase(TestCase):
    def setUp(self):
        super(FirewallRulesOperationsTestCase, self).setUp()

        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties=IntegrationTestConfig().get()['security_group'])

        network_relationship = mock.Mock()
        network_relationship.target = mock.Mock()
        network_relationship.target.instance = MockNodeInstanceContext(
            runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['test_vm']})
        self.ctx.instance.relationships = [network_relationship]

        ctx_patch1 = mock.patch('network_plugin.security_group.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        super(FirewallRulesOperationsTestCase, self).tearDown()

    def test_firewall_rules_create_delete(self):
        security_group.create()
        security_group.delete()


if __name__ == '__main__':
    unittest.main()
