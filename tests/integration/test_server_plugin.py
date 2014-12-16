import mock

from cloudify.mocks import MockCloudifyContext

from tests.integration import TestCase, IntegrationTestConfig
from server_plugin import server


class ServerPluginTestCase(TestCase):

    def setUp(self):
        super(ServerPluginTestCase, self).setUp()

        server_properties = IntegrationTestConfig().get()['server']
        name = self.name_prefix + 'server'
        server_properties['name'] = name

        self.ctx = MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={
                'server': server_properties
                }
        )
        ctx_patch1 = mock.patch('server_plugin.server.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        try:
            server.stop()
            server.delete()
        except Exception:
            pass
        super(ServerPluginTestCase, self).tearDown()

    def test_server_create_delete(self):
        server.create()
        vapp = self.vcd_client.get_vApp(
            self.ctx.node.properties['server']['name'])
        self.assertFalse(vapp is None)
        self.assertTrue(server._vm_is_on(vapp))

        server.stop()
        vapp = self.vcd_client.get_vApp(
            self.ctx.node.properties['server']['name'])
        self.assertFalse(server._vm_is_on(vapp))

        server.delete()
        vapp = self.vcd_client.get_vApp(
            self.ctx.node.properties['server']['name'])
        self.assertTrue(vapp is None)

    def test_server_stop_start(self):
        server.create()
        vapp = self.vcd_client.get_vApp(
            self.ctx.node.properties['server']['name'])
        self.assertFalse(vapp is None)
        self.assertTrue(server._vm_is_on(vapp))

        server.stop()
        vapp = self.vcd_client.get_vApp(
            self.ctx.node.properties['server']['name'])
        self.assertFalse(server._vm_is_on(vapp))

        server.start()
        vapp = self.vcd_client.get_vApp(
            self.ctx.node.properties['server']['name'])
        self.assertTrue(server._vm_is_on(vapp))
