from cosmo_tester.framework.handlers import (
    BaseHandler,
    BaseCloudifyInputsConfigReader)


class VcloudCleanupContext(BaseHandler.CleanupContext):

    def __init__(self, context_name, env):
        super(VcloudCleanupContext, self).__init__(context_name, env)

    def cleanup(self):
        super(VcloudCleanupContext, self).cleanup()


class CloudifyVcloudInputsConfigReader(BaseCloudifyInputsConfigReader):

    def __init__(self, cloudify_config, manager_blueprint_path, **kwargs):
        super(CloudifyVcloudInputsConfigReader, self).__init__(
            cloudify_config, manager_blueprint_path=manager_blueprint_path,
            **kwargs)

    @property
    def vcloud_username(self):
        return self.config['vcloud_username']

    @property
    def vcloud_password(self):
        return self.config['vcloud_password']

    @property
    def vcloud_url(self):
        return self.config['vcloud_url']

    @property
    def vcloud_service(self):
        return self.config['vcloud_service']

    @property
    def vcloud_org(self):
        return self.config['vcloud_org']

    @property
    def vcloud_vdc(self):
        return self.config['vcloud_vdc']

    @property
    def manager_server_name(self):
        return self.config['manager_server_name']

    @property
    def manager_server_catalog(self):
        return self.config['manager_server_catalog']

    @property
    def manager_server_template(self):
        return self.config['manager_server_template']

    @property
    def management_network_use_existing(self):
        return self.config['management_network_use_existing']

    @property
    def management_network_name(self):
        return self.config['management_network_name']

    @property
    def edge_gateway(self):
        return self.config['edge_gateway']

    @property
    def floating_ip_public_ip(self):
        return self.config['floating_ip_public_ip']

    @property
    def manager_private_key_path(self):
        return self.config['manager_private_key_path']

    @property
    def agent_private_key_path(self):
        return self.config['agent_private_key_path']

    @property
    def manager_public_key(self):
        return self.config['manager_public_key']

    @property
    def agent_public_key(self):
        return self.config['agent_public_key']

    @property
    def management_port_ip_allocation_mode(self):
        return self.config['management_port_ip_allocation_mode']

    @property
    def vcloud_service_type(self):
        return self.config['vcloud_service_type']

    @property
    def vcloud_region(self):
        return self.config['vcloud_region']


class VcloudHandler(BaseHandler):

    CleanupContext = VcloudCleanupContext
    CloudifyConfigReader = CloudifyVcloudInputsConfigReader

    def before_bootstrap(self):
        super(VcloudHandler, self).before_bootstrap()

    def after_bootstrap(self, provider_context):
        super(VcloudHandler, self).after_bootstrap(provider_context)


handler = VcloudHandler
