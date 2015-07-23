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
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import unittest
import mock
from cloudify import exceptions as cfy_exc
from tests.unittests import test_mock_base
from network_plugin import keypair


class NetworkPluginKeyPairpMockTestCase(test_mock_base.TestBase):

    def test_creation_validation(self):
        # exist keyfile
        fake_ctx = self.generate_node_context(
            properties={
                'private_key_path': __file__
            }
        )
        keypair.creation_validation(ctx=fake_ctx)
        # not exist keyfile
        fake_ctx = self.generate_node_context(
            properties={
                'private_key_path': __file__ + ".not_exist"
            }
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            keypair.creation_validation(ctx=fake_ctx)

    def test_create(self):
        fake_ctx =  self.generate_node_context(
            properties={'auto_generate': True})
        with mock.patch(
                'network_plugin.keypair.ctx', fake_ctx):
            with mock.patch(
                    'network_plugin.keypair._save_key_file', mock.MagicMock()):
                with mock.patch('network_plugin.keypair._generate_pair', mock.MagicMock(return_value=('public', 'private'))):
                    keypair.create()
                    prop = fake_ctx.instance.runtime_properties
                    self.assertEqual('~/.ssh/test_private.key', prop['private_key_path'])
                    self.assertEqual('private', prop['private_key_value'])
                    self.assertEqual('public', prop['public_key_value'])

        fake_ctx =  self.generate_node_context(
            properties={'auto_generate': False,
                        'private_key_value': 'private'})
        with mock.patch(
                'network_plugin.keypair.ctx', fake_ctx):
            with mock.patch(
                    'network_plugin.keypair._save_key_file', mock.MagicMock()):
                keypair.create()
                prop = fake_ctx.instance.runtime_properties
                self.assertEqual('~/.ssh/test_private.key', prop['private_key_path'])

    def test_delete(self):
        fake_ctx =  self.generate_node_context(
            properties={'auto_generate': True},
            runtime_properties={'private_key_path': 'path',
                                'private_key_value': 'private',
                                'public_key_value': 'public'})

        with mock.patch(
                'network_plugin.keypair.ctx', fake_ctx):
            with mock.patch(
                    'network_plugin.keypair._delete_key_file', mock.MagicMock()):
                prop = fake_ctx.instance.runtime_properties
                self.assertTrue('private_key_path' in prop)
                self.assertTrue('private_key_value' in prop)
                self.assertTrue('public_key_value' in prop)
                keypair.delete()
                self.assertFalse('private_key_path' in prop)
                self.assertFalse('private_key_value' in prop)
                self.assertFalse('public_key_value' in prop)

        fake_ctx =  self.generate_node_context(
            properties={'auto_generate': False,
                        'private_key_value': 'private'},
            runtime_properties={'private_key_path': 'path'})
        with mock.patch(
                'network_plugin.keypair.ctx', fake_ctx):
            with mock.patch(
                    'network_plugin.keypair._delete_key_file', mock.MagicMock()):
                prop = fake_ctx.instance.runtime_properties
                self.assertTrue('private_key_path' in prop)
                keypair.delete()
                self.assertFalse('private_key_path' in prop)


if __name__ == '__main__':
    unittest.main()
