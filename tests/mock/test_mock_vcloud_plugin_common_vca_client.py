import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
import vcloud_plugin_common


class VcloudPluginCommonVcaClientMockTestCase(test_mock_base.TestBase):
    """
        test for low level login calls
    """

    def generate_vca(self, fake_client):
        """
            generate function that return vca_client
        """
        vca = mock.MagicMock(return_value=fake_client)
        return vca

    def test_private_login(self):
        client = vcloud_plugin_common.VcloudAirClient()
        fake_client = self.generate_client()
        fake_vca_client = self.generate_vca(fake_client)
        fake_ctx = self.generate_node_context()

        def _run(
            fake_vca_client, fake_ctx, url, username, password, token,
            org_name, org_url, api_version
        ):
            with mock.patch(
                'time.sleep',
                mock.MagicMock(return_value=None)
            ):
                with mock.patch(
                    'pyvcloud.vcloudair.VCA',
                    fake_vca_client
                ):
                    with mock.patch(
                        'vcloud_plugin_common.ctx', fake_ctx
                    ):
                        return client._private_login(
                            url, username, password, token,
                            org_name, org_url, api_version
                        )

        # bad case token
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'some_url', 'root', None,
                'secret_token', 'org_name', 'org_url', 'upstream'
            )

        fake_vca_client.assert_called_with(
            service_type='vcd', username='root', host='some_url',
            version='upstream'
        )
        fake_client.login.assert_called_with(
            token='secret_token', org_url='org_url'
        )
        # bad case password
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'some_url', 'root',
                'secret_password', None, 'org_name', 'org_url',
                'upstream'
            )

        fake_vca_client.assert_called_with(
            service_type='vcd', username='root', host='some_url',
            version='upstream'
        )
        fake_client.login.assert_called_with(
            'secret_password', org='org_name'
        )
        # positive case token
        fake_client.login = mock.MagicMock(return_value=True)
        self.assertEqual(
            _run(
                fake_vca_client, fake_ctx, 'some_url', 'root', None,
                'secret_token', 'org_name', 'org_url', 'upstream'
            ),
            fake_client
        )
        # positive case password
        self.assertEqual(
            _run(
                fake_vca_client, fake_ctx, 'some_url', 'root',
                'secret_password', None, 'org_name', 'org_url',
                'upstream'
            ),
            fake_client
        )

if __name__ == '__main__':
    unittest.main()
