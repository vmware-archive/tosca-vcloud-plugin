import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
import network_plugin


class NetworkPluginMockTestCase(test_mock_base.TestBase):

    def test_get_vm_ip(self):
        fake_client = self.generate_client(vms_networks=[])
        fake_ctx = self.generate_context()
        fake_ctx._source = mock.Mock()
        fake_ctx._source.node = mock.Mock()
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'edge_gateway': 'some_edge_gateway',
                'vdc': 'vdc_name'
            }
        }
        fake_ctx._target = mock.Mock()
        fake_ctx._target.node = mock.Mock()
        # empty connections/no connection name
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                network_plugin.get_vm_ip(
                    fake_client, fake_ctx, fake_client._vdc_gateway
                )


if __name__ == '__main__':
    unittest.main()
