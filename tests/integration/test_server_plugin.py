import mock
import random
import socket
import string
import time

from cloudify import exceptions as cfy_exc
from cloudify import mocks as cfy_mocks

from server_plugin import server
from tests.integration import TestCase

RANDOM_PREFIX_LENGTH = 5


class ServerNoNetworkTestCase(TestCase):
    def setUp(self):
        super(ServerNoNetworkTestCase, self).setUp()
        chars = string.ascii_uppercase + string.digits
        self.name_prefix = ('plugin_test_{0}_'
                            .format(''.join(
                                random.choice(chars)
                                for _ in range(RANDOM_PREFIX_LENGTH)))
                            )
        server_test_dict = self.test_config['server']
        name = self.name_prefix + 'server'

        self.ctx = cfy_mocks.MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={
                'server':
                {
                    'name': name,
                    'catalog': server_test_dict['catalog'],
                    'template': server_test_dict['template'],
                    'hardware': server_test_dict['hardware'],
                    'guest_customization': server_test_dict.get('guest_customization')
                },
                'management_network': self.test_config['management_network'],
                'vcloud_config': self.vcloud_config
            }
        )
        self.ctx.node.properties['server']['guest_customization']['public_keys'] = [self.test_config['manager_keypair'],
                                                                                    self.test_config['agent_keypair']]
        self.ctx.instance.relationships = []
        ctx_patch1 = mock.patch('server_plugin.server.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        try:
            server.stop()
        except Exception:
            pass
        try:
            server.delete()
        except Exception:
            pass
        super(ServerNoNetworkTestCase, self).tearDown()

    def test_server_creation_validation(self):
        success = True
        msg = None
        try:
            server.creation_validation()
        except cfy_exc.NonRecoverableError as e:
            success = False
            msg = e.message
        self.assertTrue(success, msg)

    def test_server_creation_validation_catalog_not_found(self):
        self.ctx.node.properties['server']['catalog'] = 'fake-catalog'
        self.assertRaises(cfy_exc.NonRecoverableError,
                          server.creation_validation)

    def test_server_creation_validation_template_not_found(self):
        self.ctx.node.properties['server']['template'] = 'fake-template'
        self.assertRaises(cfy_exc.NonRecoverableError,
                          server.creation_validation)

    def test_server_creation_validation_parameter_missing(self):
        del self.ctx.node.properties['server']['template']
        self.assertRaises(cfy_exc.NonRecoverableError,
                          server.creation_validation)

    def test_server_create_delete(self):
        server.create()
        vdc = self.vca_client.get_vdc(self.vcloud_config['vdc'])
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertFalse(vapp is None)
        self.assertFalse(server._vapp_is_on(vapp))
        self.check_hardware(vapp)
        server.delete()
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertTrue(vapp is None)

    def test_server_stop_start(self):
        server.create()
        vdc = self.vca_client.get_vdc(self.vcloud_config['vdc'])
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertFalse(vapp is None)
        self.assertFalse(server._vapp_is_on(vapp))

        self._run_with_retry(server.start, self.ctx)
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertTrue(server._vapp_is_on(vapp))

        server.stop()
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertFalse(server._vapp_is_on(vapp))

        self._run_with_retry(server.start, self.ctx)
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertTrue(server._vapp_is_on(vapp))

    def check_hardware(self, vapp):
        data = vapp.get_vms_details()[0]
        hardware = self.test_config['server']['hardware']
        if hardware:
            self.assertEqual(data['cpus'], hardware['cpu'])
            self.assertEqual(data['memory'] * 1024, hardware['memory'])


class ServerWithNetworkTestCase(TestCase):
    def setUp(self):
        super(ServerWithNetworkTestCase, self).setUp()
        chars = string.ascii_uppercase + string.digits
        self.name_prefix = ('plugin_test_{0}_'
                            .format(''.join(
                                random.choice(chars)
                                for _ in range(RANDOM_PREFIX_LENGTH)))
                            )

        server_test_dict = self.test_config['server']
        name = self.name_prefix + 'server'
        self.network_name = self.test_config['management_network']

        port_node_context = cfy_mocks.MockNodeContext(
            properties={
                'port':
                {
                    'network': self.network_name,
                    'ip_allocation_mode': 'pool',
                    'primary_interface': True
                }
            }
        )

        network_node_context = cfy_mocks.MockNodeContext(
            properties={
                'network':
                {
                    'name': self.network_name
                }
            }
        )

        self.port_relationship = mock.Mock()
        self.port_relationship.target = mock.Mock()
        self.port_relationship.target.node = port_node_context

        self.network_relationship = mock.Mock()
        self.network_relationship.target = mock.Mock()
        self.network_relationship.target.node = network_node_context

        self.ctx = cfy_mocks.MockCloudifyContext(
            node_id=name,
            node_name=name,
            properties={
                'server':
                {
                    'name': name,
                    'catalog': server_test_dict['catalog'],
                    'template': server_test_dict['template']
                },
                'management_network': self.network_name,
                'vcloud_config': self.vcloud_config
            }
        )
        self.ctx.instance.relationships = []
        ctx_patch1 = mock.patch('server_plugin.server.ctx', self.ctx)
        ctx_patch2 = mock.patch('vcloud_plugin_common.ctx', self.ctx)
        ctx_patch1.start()
        ctx_patch2.start()
        self.addCleanup(ctx_patch1.stop)
        self.addCleanup(ctx_patch2.stop)

    def tearDown(self):
        try:
            server.stop()
        except Exception:
            pass
        try:
            server.delete()
        except Exception:
            pass
        super(ServerWithNetworkTestCase, self).tearDown()

    def test_create_with_port_connection(self):
        self.ctx.instance.relationships = [self.port_relationship]
        self._create_test()

    def test_create_with_network_connection(self):
        self.ctx.instance.relationships = [self.network_relationship]
        self._create_test()

    def test_create_without_connections(self):
        self.ctx.instance.relationships = []
        self._create_test()

    def _create_test(self):
        server.create()
        self._run_with_retry(server.start, self.ctx)
        vdc = self.vca_client.get_vdc(self.vcloud_config['vdc'])
        vapp = self.vca_client.get_vapp(
            vdc,
            self.ctx.node.properties['server']['name'])
        self.assertFalse(vapp is None)
        networks = server._get_vm_network_connections(vapp)
        self.assertEqual(1, len(networks))
        self.assertEqual(self.network_name, networks[0]['network_name'])

    def test_get_state(self):
        num_tries = 5
        verified = False
        server.create()
        self._run_with_retry(server.start, self.ctx)
        for _ in range(num_tries):
            result = server._get_state()
            if result is True:
                self.assertTrue('ip' in self.ctx.instance.runtime_properties)
                self.assertTrue('networks'
                                in self.ctx.instance.runtime_properties)
                self.assertEqual(1,
                                 len(self.ctx.instance.
                                     runtime_properties['networks'].keys()))
                self.assertEqual(self.network_name,
                                 self.ctx.instance.
                                 runtime_properties['networks'].keys()[0])
                ip_valid = True
                try:
                    socket.inet_aton(
                        self.ctx.instance.runtime_properties['ip'])
                except socket.error:
                    ip_valid = False
                self.assertTrue(ip_valid)
                verified = True
                break
            time.sleep(2)
        self.assertTrue(verified)
