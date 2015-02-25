import contextlib
import ipaddress
import mock
import random
import socket
import string
import time
import unittest

from cloudify import mocks as cfy_mocks

from network_plugin import floatingip, network
from server_plugin import server
from vcloud_plugin_common import get_vcloud_config, VcloudAirClient

from tests.integration import TestCase, IntegrationTestConfig

RANDOM_PREFIX_LENGTH = 5


class CombinedTestCase(TestCase):

    def setUp(self):
        super(CombinedTestCase, self).setUp()
        self.test_config = IntegrationTestConfig().get()
        chars = string.ascii_uppercase + string.digits
        self.name_prefix = ('plugin_test_{0}_'
                            .format(''.join(
                                random.choice(chars)
                                for _ in range(RANDOM_PREFIX_LENGTH)))
                            )

    def _setup_network(self):
        network_use_existing = self.test_config['combined']['network_use_existing']
        existing_network = self.test_config['combined']['network_name']
        self.network_name = (existing_network if network_use_existing
                             else self.name_prefix + "network")
        self.network_ctx = cfy_mocks.MockCloudifyContext(
            node_id=self.network_name,
            node_name=self.network_name,
            properties={
                "network": self.test_config['network'],
                "use_external_resource": network_use_existing,
                "resource_id": self.network_name
                }
        )

    def _setup_server(self, ip_allocation_mode):
        self.server_name = self.name_prefix + 'server'
        port_node_context = cfy_mocks.MockNodeContext(
            properties={
                'port':
                {
                    'network': self.network_name,
                    'ip_allocation_mode': ip_allocation_mode,
                    'primary_interface': True
                }
            }
        )
        port_relationship = mock.Mock()
        port_relationship.target = mock.Mock()
        port_relationship.target.node = port_node_context
        self.server_ctx = cfy_mocks.MockCloudifyContext(
            node_id=self.server_name,
            node_name=self.server_name,
            properties={
                'server': self.test_config['server'],
                'management_network': self.network_name
            }
        )
        self.server_ctx.instance.relationships = [port_relationship]

    def _setup_floating_ip(self):
        self.fip_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={},
            target=cfy_mocks.MockCloudifyContext(
                node_id="target",
                properties={'floatingip': self.test_config['floatingip']}),
            source=cfy_mocks.MockCloudifyContext(
                node_id="source",
                runtime_properties={server.VCLOUD_VAPP_NAME: self.server_name}
            )
        )

    def test_new_server_network_ip_allocation_dhcp(self):
        self._setup_network()

        self._setup_server(ip_allocation_mode='dhcp')

        self.addCleanup(self._delete_network)
        self._create_network()

        self.addCleanup(self._delete_server)
        self._create_server()
        self._wait_for_server_configured()

        if self.test_config['combined']['network_use_existing'] is False:
            gw_ip = self.network_ctx.node.properties['network']['gateway_ip']
            netmask = self.network_ctx.node.properties['network']['netmask']
            gw_interface = ipaddress.IPv4Interface(
                gw_ip + '/' + netmask)
            vdc = self.vca_client.get_vdc(self.vcloud_config['vdc'])
            vapp = self.vca_client.get_vapp(
                vdc,
                self.server_ctx.instance.runtime_properties[server.VCLOUD_VAPP_NAME])
            nw_connection = server._get_vm_network_connection(vapp,
                                                              self.network_name)
            self.assertTrue(ipaddress.IPv4Address(unicode(nw_connection['ip']))
                            in gw_interface.network,
                            "vm ip: {0}, expected network: {1}"
                            .format(nw_connection['ip'],
                                    gw_interface.network))

    def test_new_server_network_ip_allocation_pool(self):
        self._setup_network()

        self._setup_server(ip_allocation_mode='pool')

        self.addCleanup(self._delete_network)
        self._create_network()

        self.addCleanup(self._delete_server)
        self._create_server()
        self._wait_for_server_configured()

        if self.test_config['combined']['network_use_existing'] is False:
            gw_ip = self.network_ctx.node.properties['network']['gateway_ip']
            netmask = self.network_ctx.node.properties['network']['netmask']
            gw_interface = ipaddress.IPv4Interface(
                gw_ip + '/' + netmask)
            vdc = self.vca_client.get_vdc(self.vcloud_config['vdc'])
            vapp = self.vca_client.get_vapp(
                vdc,
                self.server_ctx.instance.runtime_properties[server.VCLOUD_VAPP_NAME])
            nw_connection = server._get_vm_network_connection(vapp,
                                                              self.network_name)
            self.assertTrue(ipaddress.IPv4Address(unicode(nw_connection['ip']))
                            in gw_interface.network,
                            "vm ip: {0}, expected network: {1}"
                            .format(nw_connection['ip'],
                                    gw_interface.network))

    def _create_network(self):
        with contextlib.nested(
            mock.patch('network_plugin.network.ctx', self.network_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.network_ctx)):
                network.create()

    def _delete_network(self):
        with contextlib.nested(
            mock.patch('network_plugin.network.ctx', self.network_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.network_ctx)):
                network.delete()

    def _create_server(self):
        with contextlib.nested(
            mock.patch('server_plugin.server.ctx', self.server_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.server_ctx)):
                server.create()
                server.start()

    def _delete_server(self):
        with contextlib.nested(
            mock.patch('server_plugin.server.ctx', self.server_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.server_ctx)):
                server.stop()
                server.delete()

    def _wait_for_server_configured(self):
        with contextlib.nested(
            mock.patch('server_plugin.server.ctx', self.server_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.server_ctx)):
                num_tries = 10
                verified = False
                for _ in range(num_tries):
                    result = server.get_state()
                    if result is True:
                        verified = True
                        break
                    time.sleep(10)
                self.assertTrue(verified,
                                "Server configuration wasn't verified")

    def _connect_floating_ip(self):
        with contextlib.nested(
            mock.patch('network_plugin.floatingip.ctx', self.fip_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.fip_ctx)):
                floatingip.connect_floatingip()

    def _disconnect_floating_ip(self):
        with contextlib.nested(
            mock.patch('network_plugin.floatingip.ctx', self.fip_ctx),
            mock.patch('vcloud_plugin_common.ctx', self.fip_ctx)):
                floatingip.disconnect_floatingip()


if __name__ == '__main__':
