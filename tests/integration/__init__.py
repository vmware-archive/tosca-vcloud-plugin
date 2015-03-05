import mock
import unittest

from cloudify import mocks as cfy_mocks

from vcloud_plugin_common import Config, get_vcloud_config, VcloudAirClient


class IntegrationTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_integration_test_config.json'

class VcloudTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config.json'

class VcloudOndemandTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config_ondemand.json'

class TestCase(unittest.TestCase):

    def setUp(self, config=None):
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={})
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.vcloud_config = get_vcloud_config()
            self.vca_client = VcloudAirClient().get(config=config)
