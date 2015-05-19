import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
from network_plugin import port


class NetworkPluginPortMockTestCase(test_mock_base.TestBase):

    def test_creation_validation(self):
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            # no port
            fake_ctx = self.generate_node_context(
                properties={}
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                port.creation_validation(ctx=fake_ctx)
            # port without allocation
            fake_ctx = self.generate_node_context(
                properties={
                    'port': {
                        'some_field': 'some_value'
                    }
                }
            )
            port.creation_validation(ctx=fake_ctx)
            # wrong allocation mode
            fake_ctx = self.generate_node_context(
                properties={
                    'port': {
                        'ip_allocation_mode': 'realy wrong'
                    }
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                port.creation_validation(ctx=fake_ctx)
            # correct allocation
            for mode in ['manual', 'dhcp', 'pool']:
                fake_ctx = self.generate_node_context(
                    properties={
                        'port': {
                            'ip_allocation_mode': mode
                        }
                    }
                )
                port.creation_validation(ctx=fake_ctx)
            # wrong manual ip
            fake_ctx = self.generate_node_context(
                properties={
                    'port': {
                        'ip_allocation_mode': 'manual',
                        'ip_address': 'a.a.a.a'
                    }
                }
            )
            with self.assertRaises(cfy_exc.NonRecoverableError):
                port.creation_validation(ctx=fake_ctx)
            # correct manual ip
            fake_ctx = self.generate_node_context(
                properties={
                    'port': {
                        'ip_allocation_mode': 'manual',
                        'ip_address': '1.1.1.1'
                    }
                }
            )
            port.creation_validation(ctx=fake_ctx)


if __name__ == '__main__':
    unittest.main()
