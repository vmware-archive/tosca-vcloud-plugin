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
from IPy import IP
from vcloud_plugin_common import with_vcd_client, wait_for_task

CREATE = 1
DELETE = 2
VCLOUD_VAPP_NAME = 'vcloud_vapp_name'


def check_ip(address):
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addres: {0}".format(address))
    return address


def get_vm_ip(vcd_client, ctx):
    vappName = ctx.source.instance.runtime_properties[VCLOUD_VAPP_NAME]
    vmName = ctx.node.properties['vm']
    vapp = vcd_client.get_vApp(vappName)
    if not vapp:
        raise cfy_exc.NonRecoverableError("Could not find vApp")
    try:
        vm_info = filter(lambda details:
                         details[0] == vmName, vapp.details_of_vms())[0]
        return vm_info[6]
    except IndexError:
        raise cfy_exc.NonRecoverableError("Could not find vm IP address")


def nat_operation(vcd_client, gateway, rule_type, original_ip, translated_ip,
                  operation):
    function = None
    operation_description = None
    any_type = None

    if rule_type == "DNAT":
        any_type = "Any"

    if operation == CREATE:
        function = gateway.add_nat_rule
        operation_description = "create"
    elif operation == DELETE:
        function = gateway.del_nat_rule
        operation_description = "delete"
    else:
        cfy_exc.NonRecoverableError("Unknown operation")

    success, task, _ = function(rule_type, original_ip, any_type,
                                translated_ip, any_type, any_type)
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not {0} {1} rule").format(operation_description, rule_type)
    wait_for_task(vcd_client, task)


def floatingip_operation(vcd_client, ctx, operation):
    gateway = vcd_client.get_gateway(ctx.node.properties['gateway'])
    if gateway:
        external_ip = check_ip(ctx.node.properties['floatingip'])
        internal_ip = check_ip(get_vm_ip(vcd_client, ctx))
        nat_operation(vcd_client, gateway, "SNAT", internal_ip, external_ip,
                      operation)
        nat_operation(vcd_client, gateway, "DNAT", external_ip, internal_ip,
                      operation)
    else:
        raise cfy_exc.NonRecoverableError("Gateway not found")


@operation
@with_vcd_client
def create(vcloud_client, **kwargs):
    # may be usefull, if use dynamic ip selection
    pass


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    pass


@operation
@with_vcd_client
def connect_floatingip(vcd_client, **kwargs):
    floatingip_operation(vcd_client, ctx, CREATE)


@operation
@with_vcd_client
def disconnect_floatingip(vcd_client, **kwargs):
    floatingip_operation(vcd_client, ctx, DELETE)
