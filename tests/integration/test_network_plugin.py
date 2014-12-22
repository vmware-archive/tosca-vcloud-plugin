import mock
import unittest

from cloudify.mocks import MockCloudifyContext, MockContext,\
    MockNodeContext, MockNodeInstanceContext

from tests.integration import TestCase
from network_plugin import floatingip
from network_plugin.floatingip import VCLOUD_VAPP_NAME


class ServerPluginTestCase(TestCase):

    def setUp(self):
        super(ServerPluginTestCase, self).setUp()

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
#        import pdb
#        pdb.set_trace()

        self.ctx.source.instance = MockNodeInstanceContext(
            runtime_properties={VCLOUD_VAPP_NAME: 'ilyashenko'})
        self.ctx.target.node = MockNodeContext(
            properties={'floatingip': '23.92.245.236',
                        'gateway': 'M966854774-4471'})
        ctx_patch1 = mock.patch('network_plugin.floatingip.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        super(ServerPluginTestCase, self).tearDown()

    def test_server_create_delete(self):
        floatingip.connect_floatingip()
        floatingip.disconnect_floatingip()

if __name__ == '__main__':
    unittest.main()
