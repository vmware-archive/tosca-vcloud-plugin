from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, wait_for_task, get_vcloud_config, get_mandatory
import collections
from network_plugin import (check_ip, is_valid_ip_range, is_separate_ranges,
                            is_ips_in_same_subnet, save_gateway_configuration,
                            get_network_name, is_network_exists)

@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    pass
