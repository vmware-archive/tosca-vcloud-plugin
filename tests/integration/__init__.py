import mock
import unittest
import time

from cloudify import mocks as cfy_mocks
from cloudify import exceptions as cfy_exceptions

from vcloud_plugin_common import Config, VcloudAirClient


class IntegrationSubscriptionTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_integration_subscription_test_config.json'


class IntegrationOndemandTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_INTEGRATION_TEST_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_integration_ondemand_test_config.json'


class VcloudSubscriptionTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config_subscription.json'


class VcloudOndemandTestConfig(Config):
    VCLOUD_CONFIG_PATH_ENV_VAR = 'VCLOUD_CONFIG_PATH'
    VCLOUD_CONFIG_PATH_DEFAULT = '~/vcloud_config_ondemand.json'


class TestCase(unittest.TestCase):
    vcloud_config = None  # class variable
    test_config = None    # class variable

    def setUp(self, config=None):
        if not self.vcloud_config:
            raise RuntimeError("vcloud_config empty")
        if not self.test_config:
            raise RuntimeError("test_config empty")

        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={})
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.vca_client = VcloudAirClient().get(config=self.vcloud_config)

    def _run_with_retry(self, func, ctx):
        while True:
            try:
                return func(ctx=ctx)
            except cfy_exceptions.OperationRetry as e:
                ctx.operation._operation_retry = None
                ctx.logger.info(format(str(e)))
                time.sleep(e.retry_after)

def prepare_test_config():
    pass


def run_tests(tests):
    configs = [(VcloudSubscriptionTestConfig().get(), IntegrationSubscriptionTestConfig().get()),
               (VcloudOndemandTestConfig().get(), IntegrationOndemandTestConfig().get())]

    loader = unittest.TestLoader().loadTestsFromTestCase
    suits = [loader(suite) for suite in tests]
    prepare_test_config()
    try:
        for config in configs:
            TestCase.vcloud_config = config[0]
            TestCase.test_config = config[1]
            for suit in suits:
                result = unittest.TextTestRunner(verbosity=2).run(suit)
                if len(result.errors):
                    raise RuntimeError("Tests FAILED!!! with {}".format(config[0]))
    except RuntimeError as e:
        print e
