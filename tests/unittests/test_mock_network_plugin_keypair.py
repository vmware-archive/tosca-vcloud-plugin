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

if __name__ == '__main__':
    unittest.main()
