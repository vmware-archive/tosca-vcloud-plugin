from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_mandatory
from network_plugin import check_ip


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    port = get_mandatory(ctx.node.properties, 'port')
    ip_allocation_mode = port.get('ip_allocation_mode')
    if ip_allocation_mode:
        if ip_allocation_mode.lower() not in ['manual', 'dhcp', 'pool']:
            raise cfy_exc.NonRecoverableError(
                "Unknown allocation mode {0}".format(ip_allocation_mode))
        ip_address = port.get('ip_address')
        if ip_address:
            check_ip(ip_address)
