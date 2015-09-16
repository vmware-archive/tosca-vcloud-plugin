# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import unittest

from cloudify import exceptions as cfy_exc
from tests.unittests import test_mock_base
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

    def test_subscription_login(self):
        client = vcloud_plugin_common.VcloudAirClient()
        fake_client = self.generate_client()
        fake_vca_client = self.generate_vca(fake_client)
        fake_ctx = self.generate_node_context()

        def _run(
            fake_vca_client, fake_ctx, url, username, password, token,
            service, org_name
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
                        with mock.patch(
                                'pyvcloud.vcloudair.VCS',
                                mock.MagicMock()):
                            with mock.patch('vcloud_plugin_common.local_session_token',
                                            None):
                                return client._subscription_login(
                                    url, username, password, token, service,
                                    org_name)
        # can't login with token
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username', None,
                'token', 'service', 'org_name'
            )
        # can't login with password
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', 'token', 'service', 'org_name'
            )
        fake_client.login = mock.MagicMock(return_value=True)
        # can't login to org with token
        with self.assertRaises(cfy_exc.RecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username', None,
                'token', 'service', 'org_name'
            )
        fake_client.login_to_org.assert_called_with(
            'service', 'org_name'
        )
        # can't login to org with password
        with self.assertRaises(cfy_exc.RecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', None, 'service', 'org_name'
            )
        # login to org with token
        fake_client.login_to_org = mock.MagicMock(return_value=True)
        self.assertEqual(
            _run(
                fake_vca_client, fake_ctx, 'url', 'username', None,
                'token', 'service', 'org_name'
            ),
            fake_client
        )
        # login to org with password
        self.assertEqual(
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', 'token', 'service', 'org_name'
            ),
            fake_client
        )

    def test_ondemand_login(self):
        client = vcloud_plugin_common.VcloudAirClient()
        fake_client = self.generate_client()
        fake_vca_client = self.generate_vca(fake_client)
        fake_ctx = self.generate_node_context()

        def _run(
            fake_vca_client, fake_ctx, url, username, password, token,
            instance_id
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
                        with mock.patch(
                                'pyvcloud.vcloudair.VCS',
                                mock.MagicMock()):
                            with mock.patch('vcloud_plugin_common.local_session_token',
                                            None):
                                return client._ondemand_login(
                                    url, username, password, token, instance_id)
        # bad case without instance
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'password', 'token', None
            )
        # bad case cant't login with token and no instance
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                None, 'token', 'some_instance'
            )
        # bad case cant't login with password and no instance
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', None, 'some_instance'
            )
        # bad case login with token, but without instance
        fake_client.login = mock.MagicMock(return_value=True)
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                None, 'token', 'some_instance'
            )
        # bad case login with paasword, but without instance
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', None, 'some_instance'
            )
        # bad case, login with token and we have instance
        # relogin next time
        fake_client.get_instances = mock.MagicMock(
            return_value=[{'id': 'some_instance'}]
        )
        with self.assertRaises(cfy_exc.RecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                None, 'token', 'some_instance'
            )
        # bad case, login with password and we have instance
        # relogin next time
        with self.assertRaises(cfy_exc.RecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', None, 'some_instance'
            )
        # positive case, login with token
        fake_client.login_to_instance = mock.MagicMock(
            return_value=True
        )
        _run(
            fake_vca_client, fake_ctx, 'url', 'username',
            None, 'token', 'some_instance'
        )
        # positive case, can login_instance with password
        fake_client.login_to_instance = mock.MagicMock(
            return_value=True
        )
        _run(
            fake_vca_client, fake_ctx, 'url', 'username',
            'secret-password', None, 'some_instance'
        )
        # negative case, can login to instance but not to system
        # login with token
        fake_client.login = mock.MagicMock(return_value=False)
        fake_client.login_to_instance = mock.MagicMock(
            return_value=True
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                None, 'token', 'some_instance'
            )
        # login with password
        fake_client.login_to_instance = mock.MagicMock(
            return_value=True
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run(
                fake_vca_client, fake_ctx, 'url', 'username',
                'secret-password', None, 'some_instance'
            )

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

        # bad case without token
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

    def test_connect(self):
        client = vcloud_plugin_common.VcloudAirClient()
        fake_client = self.generate_client()
        fake_vca_client = self.generate_vca(fake_client)
        fake_ctx = self.generate_node_context()
        fake_client.login = mock.MagicMock(return_value=True)
        fake_client.login_to_instance = mock.MagicMock(return_value=True)
        fake_client.login_to_org = mock.MagicMock(return_value=True)

        def loginc_check(fake_client):
            # wrong service type
            with self.assertRaises(cfy_exc.NonRecoverableError):
                client.connect({
                    'url': 'url',
                    'username': 'username',
                    'service_type': 'unknow',
                    'token': 'token'
                })
            # not enough fields for subscription
            service_type = vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            with self.assertRaises(cfy_exc.NonRecoverableError):
                client.connect({
                    'url': 'url',
                    'username': 'username',
                    'service_type': service_type,
                    'token': 'token'
                })
            # correct PRIVATE_SERVICE_TYPE or 'private'
            for service_type in [
                vcloud_plugin_common.PRIVATE_SERVICE_TYPE,
                'private'
            ]:
                self.assertEqual(
                    client.connect({
                        'url': 'url',
                        'username': 'username',
                        'service_type': service_type,
                        'password': 'password'
                    }),
                    fake_client
                )
                self.assertEqual(
                    client.connect({
                        'url': 'url',
                        'username': 'username',
                        'service_type': service_type,
                        'token': 'token'
                    }),
                    fake_client
                )
            # ondemand
            fake_client.get_instances = mock.MagicMock(
                return_value=[{'id': 'some_instance'}]
            )
            service_type = vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
            self.assertEqual(
                client.connect({
                    'url': 'url',
                    'username': 'username',
                    'service_type': service_type,
                    'password': 'password',
                    'instance': 'some_instance'
                }),
                fake_client
            )
            # subscription
            fake_client.get_instances = mock.MagicMock(
                return_value=[{'id': 'some_instance'}]
            )
            service_type = vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            self.assertEqual(
                client.connect({
                    'url': 'url',
                    'username': 'username',
                    'service_type': service_type,
                    'password': 'password',
                    'service': 'service',
                    'org': 'org'
                }),
                fake_client
            )

        # empty url + login + pasword/url + login + token
        with self.assertRaises(cfy_exc.NonRecoverableError):
            client.connect({})
        with self.assertRaises(cfy_exc.NonRecoverableError):
            client.connect({
                'url': 'url',
                'username': 'username'
            })
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
                    with mock.patch(
                            'pyvcloud.vcloudair.VCS',
                            mock.MagicMock()):
                        loginc_check(fake_client)

    def test_get(self):
        client = vcloud_plugin_common.VcloudAirClient()
        fake_ctx = self.generate_node_context()
        # any login will be success
        fake_client = self.generate_client()
        fake_client.login = mock.MagicMock(return_value=True)
        fake_vca_client = self.generate_vca(fake_client)
        # block io
        mock_for_raise = mock.MagicMock(side_effect=IOError('no file'))
        fake_file = mock.mock_open(mock_for_raise)
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
                    with mock.patch(
                        '__builtin__.open', fake_file
                    ):
                        self.assertEqual(
                            client.get(config={
                                'url': 'url',
                                'username': 'username',
                                'service_type': 'private',
                                'token': 'token'
                            }),
                            fake_client
                        )

if __name__ == '__main__':
    unittest.main()
