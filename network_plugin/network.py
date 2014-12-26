# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from cloudify import ctx
from cloudify.decorators import operation

from vcloud_plugin_common import with_vcd_client

VCLOUD_NETWORK_NAME = 'vcloud_network_name'


@operation
@with_vcd_client
def create(vcd_client, **kwargs):
    if ctx.node.properties['use_external_resource'] is True:
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = \
            ctx.node.properties['resource_id']
        return
    network_name = ctx.node.properties['resource_id']
    if network_name in _get_network_list(vcd_client):
        return
    ctx.node.properties["network"]["gateway_ip"]
    ctx.node.properties["network"]["netmask"]
    ctx.node.properties["network"]["dns"]
    ctx.node.properties["network"]["dns_duffix"]
    ctx.node.properties["network"]["start_address"]
    ctx.node.properties["network"]["end_address"]
    ctx.node.properties["network"]["use_gateway"]
    success, task = create(vcd_client, network_name, ctx.node.properties["network"])
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not create network{0}").format(network_name)
    wait_for_task(vcd_client, task)


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    network_name = ctx.node.properties['resource_id']
    success, task = delete(vcd_client, network_name)
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not delete network{0}").format(network_name)
    wait_for_task(vcd_client, task)

def _get_network_list(vcd_client):
    vdc=self.vcd_client._get_vdc()
    return [net.name for net in  vdc.AvailableNetworks.Network]
