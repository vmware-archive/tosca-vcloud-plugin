import random
import logging
import os
import time
import copy
from contextlib import contextmanager

from retrying import retry

from cosmo_tester.framework.handlers import (
    BaseHandler,
    BaseCloudifyInputsConfigReader)
from cosmo_tester.framework.util import get_actual_keypath


class VcloudCleanupContext(BaseHandler.CleanupContext):

    def __init__(self, context_name, env):
        super(VcloudCleanupContext, self).__init__(context_name, env)


class CloudifyVcloudInputsConfigReader(BaseCloudifyInputsConfigReader):

    def __init__(self, cloudify_config, manager_blueprint_path, **kwargs):
        super(CloudifyVcloudInputsConfigReader, self).__init__(
            cloudify_config, manager_blueprint_path=manager_blueprint_path,
            **kwargs)

class VcloudHandler(BaseHandler):

    CleanupContext = VcloudCleanupContext
    CloudifyConfigReader = CloudifyVcloudInputsConfigReader

    def before_bootstrap(self):
        super(VcloudHandler, self).before_bootstrap()

    def after_bootstrap(self, provider_context):
        super(VcloudHandler, self).after_bootstrap(provider_context)


handler = VcloudHandler
