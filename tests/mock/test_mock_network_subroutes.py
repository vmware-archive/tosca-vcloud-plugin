import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
from network_plugin import network, BUSY_MESSAGE


class NetworkSubroutesMockTestCase(test_mock_base.TestBase):

    def test__get_network_list(self):
        # check list with one network
        fake_client = self.generate_client(vdc_networks=['something'])
        self.assertEqual(
            ['something'],
            network._get_network_list(fake_client, 'vdc_name')
        )
        fake_client.get_vdc.assert_called_with('vdc_name')
        # can't get vdc
        fake_client.get_vdc = mock.MagicMock(return_value=None)
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._get_network_list(fake_client, 'vdc_name')

    def test_split_adresses(self):
        range_network = network._split_adresses("10.1.1.1-10.1.1.255")
        self.assertEqual(range_network.start, '10.1.1.1')
        self.assertEqual(range_network.end, '10.1.1.255')
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._split_adresses("10.1.1.1")
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._split_adresses("10.1.1.255-10.1.1.1")
        with self.assertRaises(cfy_exc.NonRecoverableError):
            network._split_adresses("my-10")

    def test__dhcp_operation(self):
        fake_client = self.generate_client()
        # wrong dhcp_range
        fake_ctx = self.generate_context(properties={
            'network': {
                'dhcp': {
                    'dhcp_range': ""
                },
                'edge_gateway': 'gateway'
            },
            'vcloud_config': {
                'vdc': 'vdc_name'
            }
        })
        with mock.patch('network_plugin.network.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, '_management_network', network.ADD_POOL
                    )

        fake_ctx = self.generate_context(properties={
            'network': {
                'dhcp': {
                    'dhcp_range': "10.1.1.1-10.1.1.255"
                },
                'edge_gateway': 'gateway'
            },
            'vcloud_config': {
                'vdc': 'vdc_name'
            }
        })

        with mock.patch('network_plugin.network.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                # returned error/None from server
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, '_management_network', network.ADD_POOL
                    )
                fake_client.get_gateway.assert_called_with(
                    'vdc_name', 'gateway'
                )

                # returned error/None from server delete
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, '_management_network', network.DELETE_POOL
                    )

                #returned busy, try next time
                message = fake_client._vdc_gateway.response.content
                message = message.replace(self.ERROR_PLACE, BUSY_MESSAGE)
                fake_client._vdc_gateway.response.content = message
                fake_ctx.operation.retry = mock.MagicMock(return_value=None)
                network._dhcp_operation(
                    fake_client, '_management_network',
                    network.DELETE_POOL
                ), None
                fake_ctx.operation.retry.assert_called_with(
                    message='Waiting for gateway.',
                    retry_after=10
                )

                # no such gateway
                fake_client.get_gateway = mock.MagicMock(return_value=None)
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    network._dhcp_operation(
                        fake_client, '_management_network', network.ADD_POOL
                    )

if __name__ == '__main__':
    unittest.main()
