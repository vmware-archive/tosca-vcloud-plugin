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

    success, task = network_operations.create(vcd_client, network_name,
                                              ctx.node.properties["network"])
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not create network{0}").format(network_name)
    wait_for_task(vcd_client, task)


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    network_name = ctx.node.properties["network"]["name"]\
        if "name" in ctx.node.properties["network"]\
           else ctx.node.properties['resource_id']
    success, task = network_operations.delete(vcd_client, network_name)
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not delete network{0}").format(network_name)
    wait_for_task(vcd_client, task)


def _get_network_list(vcd_client):
    vdc = vcd_client._get_vdc()
    return [net.name for net in vdc.AvailableNetworks.Network]
