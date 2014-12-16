import random
import string
import unittest

from vcloud_plugin_common import Config, VcloudDirectorClient

RANDOM_PREFIX_LENGTH = 5


class IntegrationTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_intergation_test_config.json'


class TestCase(unittest.TestCase):

    def setUp(self):
        self.vcd_client = VcloudDirectorClient().get()
        chars = string.ascii_uppercase + string.digits
        self.name_prefix = ('plugin_test_{0}_'
                            .format(''.join(
                                random.choice(chars)
                                for _ in range(RANDOM_PREFIX_LENGTH)))
                            )
