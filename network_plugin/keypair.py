from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config
from network_plugin import check_ip, get_vm_ip, save_gateway_configuration


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    pass
