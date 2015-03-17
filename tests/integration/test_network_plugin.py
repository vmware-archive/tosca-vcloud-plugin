import mock
import unittest
from cloudify.mocks import MockCloudifyContext
from network_plugin import floatingip, network, security_group, public_nat, keypair, port
from server_plugin.server import VCLOUD_VAPP_NAME
from network_plugin.network import VCLOUD_NETWORK_NAME
from network_plugin import CheckAssignedExternalIp
from cloudify import exceptions as cfy_exc
from tests.integration import TestCase, IntegrationTestConfig, VcloudTestConfig, VcloudOndemandTestConfig
# for skipping test add this before test function:
# @unittest.skip("skip test")


class ValidationOperationsTestCase(TestCase):
    def setUp(self):
        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={})
        ctx_patch = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch.start()
        self.addCleanup(ctx_patch.stop)
        super(ValidationFloatingIPOperationsTestCase, self).setUp()

    def test_validation(self):

        self.ctx.node.properties.update({'floatingip': IntegrationTestConfig().get()['floatingip']})
        with mock.patch('network_plugin.floatingip.ctx', self.ctx) as _:
            floatingip.creation_validation()
        self.ctx.node.properties.clear()

        self.ctx.node.properties.update({'private_key_path': "test_network_plugin.py"})
        with mock.patch('network_plugin.keypair.ctx', self.ctx) as _:
            keypair.creation_validation()
        self.ctx.node.properties.clear()

        self.ctx.node.properties.update(
            {"resource_id": IntegrationTestConfig().get()['network']['name'],
             "network": IntegrationTestConfig().get()['network'],
             "use_external_resource": False})
        with mock.patch('network_plugin.network.ctx', self.ctx) as _:
            network.creation_validation()
        self.ctx.node.properties.clear()

        self.ctx.node.properties.update(
            {'port': {
                'network': IntegrationTestConfig().get()['management_network'],
                'ip_allocation_mode': 'dhcp',
                'primary_interface': True}})
        with mock.patch('network_plugin.port.ctx', self.ctx) as _:
            port.creation_validation()
        self.ctx.node.properties.clear()

        self.ctx.node.properties.update(
            {"nat": IntegrationTestConfig().get()['public_nat']['nat'],
             "rules": IntegrationTestConfig().get()['public_nat']['rules_net']})
        with mock.patch('network_plugin.public_nat.ctx', self.ctx) as _:
            public_nat.creation_validation()
        self.ctx.node.properties.clear()

        self.ctx.node.properties.update(IntegrationTestConfig().get()['security_group'])
        with mock.patch('network_plugin.security_group.ctx', self.ctx) as _:
            security_group.creation_validation()
        self.ctx.node.properties.clear()


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
        CheckAssignedExternalIp(public_ip, self._get_gateway())
        floatingip.connect_floatingip()
        self.assertRaises(cfy_exc.NonRecoverableError,
                          CheckAssignedExternalIp, public_ip, self._get_gateway())
        floatingip.disconnect_floatingip()
        CheckAssignedExternalIp(public_ip, self._get_gateway())

    def test_floating_ip_create_delete_with_autoget_ip(self):
        self.ctx.target.node.properties['floatingip'].update(IntegrationTestConfig().get()['floatingip'])
        del self.ctx.target.node.properties['floatingip']['public_ip']
        floatingip.connect_floatingip()
        public_ip = self.ctx.target.instance.runtime_properties['public_ip']
        self.assertRaises(cfy_exc.NonRecoverableError,
                          CheckAssignedExternalIp, public_ip, self._get_gateway())
        self.assertTrue(public_ip)
        floatingip.disconnect_floatingip()
        CheckAssignedExternalIp(public_ip, self._get_gateway())

    def _get_gateway(self):
        return self.vca_client.get_gateway(VcloudTestConfig().get()["vdc"],
                                           self.ctx.target.node.properties['floatingip']['edge_gateway'])


class OndemandFloatingIPOperationsTestCase(TestCase):
    def setUp(self):
        name = "testnode"
        self.gateway_name = 'gateway'
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={},
            target=MockCloudifyContext(node_id="target",
                                       properties={'floatingip': {}}),
            source=MockCloudifyContext(node_id="source",
                                       properties={'vcloud_config': VcloudOndemandTestConfig().get()},
                                       runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['test_vm'] + "-VApp"}))
        ctx_patch1 = mock.patch('network_plugin.floatingip.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)
        super(OndemandFloatingIPOperationsTestCase, self).setUp(VcloudOndemandTestConfig().get())

    def tearDown(self):
        super(OndemandFloatingIPOperationsTestCase, self).tearDown()

    def test_floating_ip_create_delete_with_autoget_ip(self):
        self.ctx.target.node.properties['floatingip'].update(IntegrationTestConfig().get()['floatingip'])
        self.ctx.target.node.properties['floatingip']['edge_gateway'] = self.gateway_name
        del self.ctx.target.node.properties['floatingip']['public_ip']
        floatingip.connect_floatingip()
        public_ip = self.ctx.target.instance.runtime_properties['public_ip']
        self.assertRaises(cfy_exc.NonRecoverableError,
                          CheckAssignedExternalIp, public_ip, self._get_gateway())
        floatingip.disconnect_floatingip()
        CheckAssignedExternalIp(public_ip, self._get_gateway())

    def _get_gateway(self):
        return self.vca_client.get_gateway(VcloudOndemandTestConfig().get()['vdc'], self.gateway_name)


class OrgNetworkOperationsTestCase(TestCase):
    def setUp(self):

        self.net_name = IntegrationTestConfig().get()['network']['name']
        self.existing_net_name = IntegrationTestConfig().get()['test_network_name']
        self.ctx = MockCloudifyContext(
            node_id=self.net_name,
            node_name=self.net_name,
            properties={"resource_id": self.existing_net_name,
                        "network": IntegrationTestConfig().get()['network'],
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
                                       properties={"nat": IntegrationTestConfig().get()['public_nat']['nat'],
                                                   "rules": {}}),
            source=MockCloudifyContext(node_id="source",
                                       properties={},
                                       runtime_properties={VCLOUD_VAPP_NAME: IntegrationTestConfig().get()['public_nat']['test_vm'],
                                                           VCLOUD_NETWORK_NAME: IntegrationTestConfig().get()['public_nat']['network_name']}))
        ctx_patch1 = mock.patch('network_plugin.public_nat.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)
        super(PublicNatOperationsTestCase, self).setUp()

    def tearDown(self):
        super(PublicNatOperationsTestCase, self).tearDown()

    def test_public_network_connected_to_nat(self):
        self.ctx.target.node.properties['rules'] = IntegrationTestConfig().get()['public_nat']['rules_net']
        self.ctx.source.node.properties['resource_id'] = IntegrationTestConfig().get()['public_nat']['network_name']
        rules_count = self.get_rules_count()
        public_nat.net_connect_to_nat()
        self.assertEqual(rules_count + 1, self.get_rules_count())
        public_nat.net_disconnect_from_nat()
        self.assertEqual(rules_count, self.get_rules_count())

    def test_public_server_connected_to_nat(self):
        self.ctx.target.node.properties['rules'] = IntegrationTestConfig().get()['public_nat']['rules_port']
        rules_count = self.get_rules_count()
        public_nat.server_connect_to_nat()
        self.assertEqual(rules_count + 2, self.get_rules_count())
        public_nat.server_disconnect_from_nat()
        self.assertEqual(rules_count, self.get_rules_count())

    def get_rules_count(self):
        return len(self._get_gateway().get_nat_rules())

    def _get_gateway(self):
        return self.vca_client.get_gateway(VcloudTestConfig().get()["vdc"],
                                           self.ctx.target.node.properties['nat']['edge_gateway'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
