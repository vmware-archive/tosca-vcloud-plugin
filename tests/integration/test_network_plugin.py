import mock
import unittest

from cloudify.mocks import MockCloudifyContext, MockContext

from tests.integration import TestCase, IntegrationTestConfig
from network_plugin import floatingip

class ServerPluginTestCase(TestCase):

    def setUp(self):
        super(ServerPluginTestCase, self).setUp()

        source_node = MockContext(
            values={
                'floatingip': '23.92.245.236'
                })

        self.ctx = MockCloudifyContext(
            source=source_node,
            properties={
                'server' : {'name' : 'mytest-VApp'},
                'vm' : {'name' : 'mytest'}}
        )
        ctx_patch1 = mock.patch('network_plugin.floatingip.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        super(ServerPluginTestCase, self).tearDown()

    def test_server_create_delete(self):
        floatingip.connect_floatingip(self.vcd_client)
        floatingip.disconnect_floatingip(self.vcd_client)
        
if __name__ == '__main__':
    unittest.main()
