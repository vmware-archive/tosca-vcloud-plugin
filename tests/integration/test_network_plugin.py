import mock
import unittest

from cloudify.mocks import MockCloudifyContext, MockContext,\
    MockNodeContext, MockNodeInstanceContext

from tests.integration import TestCase
from network_plugin import floatingip
from network_plugin.floatingip import VCLOUD_VAPP_NAME


class NatRulesOperationsTestCase(TestCase):

    def setUp(self):
        super(NatRulesOperationsTestCase, self).setUp()

        name = "testnode"
        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={},
            target=MockContext({
                'instance': None,
                'node': None
            }),
            source=MockContext({
                'instance': None,
                'node': None
            }))

        self.public_ip = '23.92.245.236'
        self.ctx.source.instance = MockNodeInstanceContext(
            runtime_properties={VCLOUD_VAPP_NAME: 'ilyashenko'})
        self.ctx.target.node = MockNodeContext(
            properties={'floatingip': {'public_ip': self.public_ip,
                                       'gateway': 'M966854774-4471'}})
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
            self.ctx.target.node.properties['floatingip']['gateway'])
        if gateway:
            for natRule in gateway.get_nat_rules():
                rule = natRule.get_GatewayNatRule()
                rule_type = natRule.get_RuleType()
                if rule_type == "DNAT":
                    ips.append(rule.get_OriginalIp())
                else:
                    ips.append(rule.get_TranslatedIp())
        return ips


if __name__ == '__main__':
    unittest.main()
