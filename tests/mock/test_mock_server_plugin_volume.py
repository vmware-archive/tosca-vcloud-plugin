import mock
import unittest

from cloudify import exceptions as cfy_exc
from cloudify import mocks as cfy_mocks
from server_plugin import volume
import test_mock_base


class ServerPluginServerMockTestCase(test_mock_base.TestBase):

    def test_creation_validation(self):
        fake_client = self.generate_client()
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        fake_client.get_disks = mock.MagicMock(return_value=[])
        # without use external without resorse_id
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        fake_client.get_disks.assert_called_with('vdc_name')
        # with resource id, but without disks(no disks for this client)
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'resource_id': 'some',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        # good case
        disk = [mock.Mock()]
        disk[0].name = 'some'
        fake_client.get_disks = mock.MagicMock(return_value=[disk])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.creation_validation(ctx=fake_ctx)

if __name__ == '__main__':
    unittest.main()
