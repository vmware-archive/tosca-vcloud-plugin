import mock
import unittest
from cloudify.mocks import MockCloudifyContext, MockNodeInstanceContext
from tests.integration import TestCase
from network_plugin import floatingip, network
from network_plugin.floatingip import VCLOUD_VAPP_NAME
from network_plugin import isExternalIpAssigned
from cloudify import exceptions as cfy_exc

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

    def test_nat_rules_create_delete_with_explicit_ip(self):
        self.ctx.node.properties['floatingip'].clear()
        self.ctx.node.properties['floatingip'].update({'public_ip': self.public_ip,
                                                       'gateway': 'M966854774-4471'})
        check_external = lambda: isExternalIpAssigned(self.public_ip, self._get_gateway())
        self.assertFalse(check_external())
        floatingip.connect_floatingip()
        self.assertTrue(check_external())
        self.assertRaises(cfy_exc.NonRecoverableError, floatingip.connect_floatingip)
        floatingip.disconnect_floatingip()
        self.assertFalse(check_external())

    def test_nat_rules_create_delete_with_autoget_ip(self):
        self.ctx.node.properties['floatingip'].clear()
        self.ctx.node.properties['floatingip'].update({'gateway': 'M966854774-4471'})

        floatingip.connect_floatingip()
        public_ip = self.ctx.instance.runtime_properties['public_ip']
        check_external = lambda: isExternalIpAssigned(public_ip, self._get_gateway())
        self.assertTrue(public_ip)
        self.assertTrue(check_external())
        self.assertRaises(cfy_exc.NonRecoverableError, floatingip.connect_floatingip)
        floatingip.disconnect_floatingip()
        self.assertFalse(check_external())

    def _get_gateway(self):
        return self.vcd_client.get_gateway(
            self.ctx.node.properties['floatingip']['gateway'])


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

    @unittest.skip("demonstrating skipping")
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
