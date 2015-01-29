import unittest

from vcloud_plugin_common import Config, VcloudDirectorClient


class IntegrationTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_integration_test_config.json'


class TestCase(unittest.TestCase):

    def setUp(self):
        self.vcd_client = VcloudDirectorClient().get()
