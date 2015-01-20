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
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vcd_client, wait_for_task
import network_operations

VCLOUD_NETWORK_NAME = 'vcloud_network_name'


@operation
@with_vcd_client
def create(vcd_client, **kwargs):
    if ctx.node.properties['use_external_resource'] is True:
        # TODO add check valid resource_id
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = \
            ctx.node.properties['resource_id']
        ctx.logger.info("External resource has been used")
        return
    network_name = ctx.node.properties["network"]["name"]\
        if "name" in ctx.node.properties["network"]\
           else ctx.node.properties['resource_id']
    if network_name in _get_network_list(vcd_client):
        ctx.logger.info("Network {0} already exists".format(network_name))
        return

    success, result = network_operations.create_network(vcd_client, network_name,
                                                        ctx.node.properties["network"])
    if success:
        ctx.logger.info("Network {0} has been successful created.".format(network_name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Could not create network{0}: {1}".format(network_name, result))
    wait_for_task(vcd_client, result)
    _dhcp_operation(vcd_client, ctx, network_operations.add_pool)


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    if ctx.node.properties['use_external_resource'] is True:
        del ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        ctx.logger.info("Network was not deleted - external resource has"
                        " been used")
        return
    _dhcp_operation(vcd_client, ctx, network_operations.delete_pool)
    network_name = ctx.node.properties["network"]["name"]\
        if "name" in ctx.node.properties["network"]\
           else ctx.node.properties['resource_id']
    success, task = network_operations.delete_network(vcd_client, network_name)
    if success:
        ctx.logger.info("Network {0} has been successful deleed.".format(network_name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Could not delete network{0}").format(network_name)
    wait_for_task(vcd_client, task)


def _get_network_list(vcd_client):
    vdc = vcd_client._get_vdc()
    return [net.name for net in vdc.AvailableNetworks.Network]


def _dhcp_operation(vcd_client, ctx, operation):
    if 'dhcp' not in ctx.node.properties or not ctx.node.properties['dhcp']:
        return
    dhcp_settings = ctx.node.properties['dhcp']
    network_name = ctx.node.properties['resource_id']
    success, task = network_operations.dhcp_pool_operation(vcd_client, network_name,
                                                           dhcp_settings, operation)
    if success:
        if operation == network_operations.add_pool:
            ctx.logger.info("DHCP rule successful created for network {0}".format(network_name))
        if operation == network_operations.delete_pool:
            ctx.logger.info("DHCP rule successful deleted for network {0}".format(network_name))
    else:
        raise cfy_exc.NonRecoverableError("Could not add DHCP pool")
    wait_for_task(vcd_client, task)
