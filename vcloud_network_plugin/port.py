# Copyright (c) 2015-2020 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_mandatory
from vcloud_network_plugin import check_ip


@operation(resumable=True)
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """
        validate port settings,
        ip_allocation_mode must be in 'manual', 'dhcp', 'pool',
        and valid ip_address if set
    """
    # combine properties
    obj = {}
    obj.update(ctx.node.properties)
    obj.update(kwargs)
    # get port
    port = get_mandatory(obj, 'port')
    ip_allocation_mode = port.get('ip_allocation_mode')
    if ip_allocation_mode:
        if ip_allocation_mode.lower() not in ['manual', 'dhcp', 'pool']:
            raise cfy_exc.NonRecoverableError(
                "Unknown allocation mode {0}".format(ip_allocation_mode))
        ip_address = port.get('ip_address')
        if ip_address:
            check_ip(ip_address)
