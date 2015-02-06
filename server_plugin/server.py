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
from cloudify import exceptions as cfy_exc

from vcloud_plugin_common import (transform_resource_name,
                                  wait_for_task,
                                  with_vcd_client)
from server_plugin import VAppOperations, MockCustomization
from mock import patch
VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
STATUS_POWER_ON = 'Powered on'
STATUS_POWER_OFF = 'Power off'
GUEST_CUSTOMIZATION = 'guest_customization'
HARDWARE = 'hardware'


@operation
@with_vcd_client
def create(vcd_client, **kwargs):
    server = {
        'name': ctx.instance.id,
    }
    server.update(ctx.node.properties['server'])
    transform_resource_name(server, ctx)
    required_params = ('catalog', 'template')
    missed_params = set(required_params) - set(server.keys())
    if len(missed_params) > 0:
        raise cfy_exc.NonRecoverableError(
            "{0} server properties must be specified"
            .format(list(missed_params)))

    vapp_name = server['name']
    vapp_template = server['template']
    vapp_catalog = server['catalog']

    create_args = {
        '--deploy': False,
        '--on': False,
        '--blocking': False,
        '--network': None,
        }
    ctx.logger.info("Creating VApp with parameters: {0}".format(str(server)))

    cpu = None
    memory = None
    if HARDWARE in server and server[HARDWARE]:
        hardware = server[HARDWARE]
        cpu = hardware.get('cpu')
        memory = hardware.get('memory')
    with patch('pyvcloud.vapp.VAPP.create_instantiateVAppTemplateParams',  new=MockCustomization(vcd_client.headers,
                                                                                                 cpu=cpu, memory=memory)):
        success, result = vcd_client.create_vApp(vapp_name, vapp_template,
                                                 vapp_catalog, create_args)
    if success is False:
        raise cfy_exc.NonRecoverableError(
            "Could not create vApp: {0}".format(result))

    task = result.get_Tasks().get_Task()[0]
    wait_for_task(vcd_client, task)

    ctx.instance.runtime_properties[VCLOUD_VAPP_NAME] = server['name']

    ports = _get_connected_ports(ctx.instance.relationships)

    vapp = vcd_client.get_vApp(vapp_name)
    vapp_ops = VAppOperations(vcd_client, vapp)

    success, result = vapp_ops.rename_vm(server['name'])
    if success is False:
        raise cfy_exc.NonRecoverableError("Could not rename VM")
    wait_for_task(vcd_client, result)

    if len(ports) > 0:
        for index, port in enumerate(ports):
            port_properties = port.node.properties['port']
            network_name = port_properties['network']

            success, result = vapp_ops.add_network(network_name,
                                                   'bridged')
            if success is False:
                raise cfy_exc.NonRecoverableError(
                    "Could not add network {0} to VApp {1}: {2}"
                    .format(network_name, vapp_name, result))
            wait_for_task(vcd_client, result)

            connections_primary_index = None
            if port_properties.get('primary_interface'):
                connections_primary_index = index
            ip_address = port_properties.get('ip_address')
            mac_address = port_properties.get('mac_address')
            ip_allocation_mode = port_properties.get('ip_allocation_mode',
                                                     'DHCP').upper()
            connection_args = {
                'network_name': network_name,
                'connection_index': index,
                'connections_primary_index': connections_primary_index,
                'ip_allocation_mode': ip_allocation_mode,
                'mac_address': mac_address,
                'ip_address': ip_address
                }
            ctx.logger.info("Connecting network with parameters {0}"
                            .format(str(connection_args)))
            success, result = vapp_ops.connect_network(**connection_args)
            if success is False:
                raise cfy_exc.NonRecoverableError(
                    "Could not connect vApp {0} to network {1}: {2}"
                    .format(vapp_name, network_name, result))
            wait_for_task(vcd_client, result)

    if GUEST_CUSTOMIZATION in server and server[GUEST_CUSTOMIZATION]:
        custom = server[GUEST_CUSTOMIZATION]
        script = None
        password = None
        computer_name = None
        if 'script' in custom:
            script = custom['script']
        if 'admin_password' in custom:
            password = custom['admin_password']
        if 'admin_password' in custom:
            password = custom['admin_password']
        if 'computer_name' in custom:
            computer_name = custom['computer_name']
        success, result = vapp_ops.update_guest_customization(enabled=True,
                                                              admin_password=password,
                                                              computer_name=computer_name,
                                                              customization_script=script)
        if success is False:
            raise cfy_exc.NonRecoverableError(
                "Could not set guest customization script: {}".format(result))
        wait_for_task(vcd_client, result)
        # This function avialable from API version 5.6
        if vapp_ops.customize_on_next_poweron():
            ctx.logger.info("Customizations sucsessful")
        else:
            raise cfy_exc.NonRecoverableError("Can't run customization in next power on")
    else:
        success, result = vapp_ops.update_guest_customization(enable=False)
        if success is False:
            raise cfy_exc.NonRecoverableError(
                "Could not disable guest customization: {}".format(result))
        wait_for_task(vcd_client, result)


@operation
@with_vcd_client
def start(vcd_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    vapp = vcd_client.get_vApp(vapp_name)
    if _vm_is_on(vapp) is False:
        ctx.logger.info("Power-on VApp {0}".format(vapp_name))
        vapp.poweron({'--blocking': True, '--json': True})


@operation
@with_vcd_client
def stop(vcd_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    vapp = vcd_client.get_vApp(vapp_name)
    ctx.logger.info("Power-off and undeploy VApp {0}".format(vapp_name))
    vapp.undeploy({'--blocking': True, '--json': True, '--action': 'powerOff'})


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    vapp = vcd_client.get_vApp(vapp_name)
    ctx.logger.info("Deleting VApp {0}".format(vapp_name))
    vapp.delete({'--blocking': True, '--json': True})
    del ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]


@operation
@with_vcd_client
def get_state(vcd_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    vapp = vcd_client.get_vApp(vapp_name)
    vapp_ops = VAppOperations(vcd_client, vapp)
    nw_connections = _get_vm_network_connections(vapp_ops)
    if len(nw_connections) == 0:
        ctx.logger.info("No networks connected")
        ctx.instance.runtime_properties['ip'] = None
        ctx.instance.runtime_properties['networks'] = {}
        return True
    management_network_name = ctx.node.properties['management_network']
    networks = {}
    for connection in nw_connections:
        networks[connection['network_name']] = connection['ip']
        if connection['network_name'] == management_network_name:
            ctx.logger.info("Management network ip address {0}"
                            .format(connection['ip']))
            if connection['ip']:
                ctx.instance.runtime_properties['ip'] = connection['ip']
                ctx.instance.runtime_properties['networks'] = networks
                return True
    return False


def _vm_is_on(vapp):
    return vapp.details_of_vms()[0][1] == STATUS_POWER_ON


def _get_vm_network_connections(vapp):
    connections = vapp.get_vms_network_info()[0]
    return filter(lambda network: network['is_connected'], connections)


def _get_connected_ports(relationships):
    return [relationship.target for relationship in relationships
            if 'port' in relationship.target.node.properties]
