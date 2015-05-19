import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
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
