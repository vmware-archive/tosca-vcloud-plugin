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

import unittest
import mock
from cloudify import exceptions as cfy_exc
from tests.unittests import test_mock_base
from vcloud_network_plugin import keypair


class NetworkPluginKeyPairpMockTestCase(test_mock_base.TestBase):

    def test_creation_validation(self):
        # exist keyfile
        fake_ctx = self.generate_node_context(
            properties={
                'private_key': {'path': __file__}
            }
        )
        keypair.creation_validation(ctx=fake_ctx)
        # not exist keyfile
        fake_ctx = self.generate_node_context(
            properties={
                'private_key': {'path': __file__ + ".not_exist"}
            }
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            keypair.creation_validation(ctx=fake_ctx)

    def test_create(self):
        patcher1 = mock.patch('vcloud_network_plugin.keypair._save_key_file',
                              mock.MagicMock())
        patcher2 = mock.patch('vcloud_network_plugin.keypair._generate_pair',
                              mock.MagicMock(return_value=('public',
                                                           'private')))
        patcher3 = mock.patch('vcloud_network_plugin.keypair._create_path',
                              mock.MagicMock(return_value=(
                                  '~/.ssh/test_private.key')))
        patcher1.start()
        patcher2.start()
        patcher3.start()

        fake_ctx = self.generate_node_context(
            properties={'auto_generate': True,
                        'private_key': {'create_file': True}})
        keypair.create(ctx=fake_ctx)
        prop = fake_ctx.instance.runtime_properties
        self.assertEqual('~/.ssh/test_private.key',
                         prop['private_key']['path'])
        self.assertEqual('private', prop['private_key']['key'])
        self.assertEqual('public', prop['public_key']['key'])

        fake_ctx = self.generate_node_context(
            properties={'auto_generate': False,
                        'private_key': {'key': 'private',
                                        'create_file': True}})
        keypair.create(ctx=fake_ctx)
        prop = fake_ctx.instance.runtime_properties
        self.assertEqual('~/.ssh/test_private.key',
                         prop['private_key']['path'])
        mock.patch.stopall()

    def test_delete(self):
        patcher = mock.patch('vcloud_network_plugin.keypair._delete_key_file',
                             mock.MagicMock())
        patcher.start()

        fake_ctx = self.generate_node_context(
            properties={'auto_generate': True},
            runtime_properties={'private_key': {'path': 'path',
                                                'key': 'private'},
                                'public_key': {'key': 'public'}})
        prop = fake_ctx.instance.runtime_properties
        self.assertTrue('path' in prop['private_key'])
        self.assertTrue('key' in prop['private_key'])
        self.assertTrue('key' in prop['public_key'])
        keypair.delete(ctx=fake_ctx)
        self.assertFalse('private_key' in prop)
        self.assertFalse('public_key' in prop)

        fake_ctx = self.generate_node_context(
            properties={'auto_generate': False,
                        'private_key': {'key': 'private'}},
            runtime_properties={'private_key': {'path': 'path'},
                                'public_key': {}})
        prop = fake_ctx.instance.runtime_properties
        self.assertTrue('path' in prop['private_key'])
        keypair.delete(ctx=fake_ctx)
        self.assertFalse('private_key' in prop)
        self.assertFalse('public_key' in prop)

        mock.patch.stopall()

    def test_generate_pair(self):
        public, private = keypair._generate_pair()
        self.assertTrue(public)
        self.assertTrue(private)

    def test_create_path(self):
        fake_ctx = mock.MagicMock()
        fake_ctx._local = True
        fake_ctx.instance = mock.MagicMock()
        fake_ctx.instance.id = 'id'
        fake_ctx._context = {}
        fake_ctx._context['storage'] = mock.MagicMock()
        fake_ctx._context['storage']._storage_dir = 'storage_dir'
        patcher1 = mock.patch('vcloud_network_plugin.keypair.ctx', fake_ctx)
        patcher2 = mock.patch('vcloud_network_plugin.keypair.os.environ',
                              {'VIRTUALENV': '/path/to/dir'})
        patcher1.start()
        patcher2.start()
        path = keypair._create_path()
        self.assertEqual('storage_dir/id_private.key', path)

        patcher1.stop()
        fake_ctx._local = False
        patcher1 = mock.patch('vcloud_network_plugin.keypair.ctx', fake_ctx)
        patcher1.start()
        path = keypair._create_path()
        self.assertEqual('/path/to/id_private.key', path)

        mock.patch.stopall()

    def test_save_key_file(self):
        fake_file = mock.mock_open()
        with mock.patch(
                '__builtin__.open', fake_file, create=True):
            with mock.patch(
                    'vcloud_network_plugin.keypair.chmod'):
                keypair._save_key_file('/path/to/file/', 'private')
        handle = fake_file()
        handle.write.assert_called_once_with('private')

    def test_delete_key_file(self):
        with mock.patch(
                'vcloud_network_plugin.keypair.os.unlink'):
            keypair._delete_key_file('/path/')

if __name__ == '__main__':
    unittest.main()
