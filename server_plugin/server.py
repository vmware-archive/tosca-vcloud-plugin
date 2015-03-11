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
import random
import string
from cloudify import ctx
from cloudify.decorators import operation
from cloudify import exceptions as cfy_exc

from vcloud_plugin_common import (get_vcloud_config,
                                  transform_resource_name,
                                  wait_for_task,
                                  with_vca_client,
                                  STATUS_POWERED_ON)

from network_plugin import get_network_name, get_network, is_network_exists

VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
GUEST_CUSTOMIZATION = 'guest_customization'
HARDWARE = 'hardware'
DEFAULT_EXECUTOR = "/bin/bash"
DEFAULT_USER = "ubuntu"
DEFAULT_HOME = "/home"


@operation
@with_vca_client
def create(vca_client, **kwargs):
    config = get_vcloud_config()
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

    ctx.logger.info("Creating VApp with parameters: {0}".format(str(server)))
    task = vca_client.create_vapp(config['vdc'],
                                  vapp_name,
                                  vapp_template,
                                  vapp_catalog,
                                  vm_name=vapp_name)

    if not task:
        raise cfy_exc.NonRecoverableError("Could not create vApp: {0}"
                                          .format(vca_client.response.content))

    wait_for_task(vca_client, task)
    ctx.instance.runtime_properties[VCLOUD_VAPP_NAME] = vapp_name
    connections = _create_connections_list(vca_client)

    if connections:
        for index, connection in enumerate(connections):
            vdc = vca_client.get_vdc(config['vdc'])
            vapp = vca_client.get_vapp(vdc, vapp_name)
            if vapp is None:
                raise cfy_exc.NonRecoverableError(
                    "vApp {0} could not be found".format(vapp_name))

            network_name = connection.get('network')
            network = get_network(vca_client, network_name)

            task = vapp.connect_to_network(network_name, network.get_href())
            if not task:
                raise cfy_exc.NonRecoverableError(
                    "Could not add network {0} to VApp {1}"
                    .format(network_name, vapp_name))
            wait_for_task(vca_client, task)

            connections_primary_index = None
            if connection.get('primary_interface'):
                connections_primary_index = index
            ip_address = connection.get('ip_address')
            mac_address = connection.get('mac_address')
            ip_allocation_mode = connection.get('ip_allocation_mode',
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
            task = vapp.connect_vms(**connection_args)
            if task is None:
                raise cfy_exc.NonRecoverableError(
                    "Could not connect vApp {0} to network {1}"
                    .format(vapp_name, network_name))
            wait_for_task(vca_client, task)

    custom = server.get(GUEST_CUSTOMIZATION)
    if custom:
        vdc = vca_client.get_vdc(config['vdc'])
        vapp = vca_client.get_vapp(vdc, vapp_name)
        script = _build_script(custom)
        password = custom.get('admin_password')
        computer_name = custom.get('computer_name')

        task = vapp.customize_guest_os(
            vapp_name,
            customization_script=script,
            computer_name=computer_name,
            admin_password=password
        )
        if task is None:
            raise cfy_exc.NonRecoverableError(
                "Could not set guest customization parameters")
        wait_for_task(vca_client, task)
        # This function avialable from API version 5.6
        if vapp.customize_on_next_poweron():
            ctx.logger.info("Customizations successful")
        else:
            raise cfy_exc.NonRecoverableError(
                "Can't run customization in next power on")


@operation
@with_vca_client
def start(vca_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    config = get_vcloud_config()
    vdc = vca_client.get_vdc(config['vdc'])
    vapp = vca_client.get_vapp(vdc, vapp_name)
    if _vapp_is_on(vapp) is False:
        ctx.logger.info("Power-on VApp {0}".format(vapp_name))
        task = vapp.poweron()
        if not task:
            raise cfy_exc.NonRecoverableError("Could not create vApp")
        wait_for_task(vca_client, task)


@operation
@with_vca_client
def stop(vca_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    config = get_vcloud_config()
    vdc = vca_client.get_vdc(config['vdc'])
    vapp = vca_client.get_vapp(vdc, vapp_name)
    ctx.logger.info("Power-off and undeploy VApp {0}".format(vapp_name))
    task = vapp.undeploy()
    if not task:
        raise cfy_exc.NonRecoverableError("Could not undeploy vApp")
    wait_for_task(vca_client, task)


@operation
@with_vca_client
def delete(vca_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    config = get_vcloud_config()
    vdc = vca_client.get_vdc(config['vdc'])
    vapp = vca_client.get_vapp(vdc, vapp_name)
    ctx.logger.info("Deleting VApp {0}".format(vapp_name))
    task = vapp.delete()
    if not task:
        raise cfy_exc.NonRecoverableError("Could not delete vApp")
    wait_for_task(vca_client, task)
    del ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]


@operation
@with_vca_client
def get_state(vca_client, **kwargs):
    vapp_name = ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]
    config = get_vcloud_config()
    vdc = vca_client.get_vdc(config['vdc'])
    vapp = vca_client.get_vapp(vdc, vapp_name)
    nw_connections = _get_vm_network_connections(vapp)
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


def _vapp_is_on(vapp):
    return vapp.me.get_status() == STATUS_POWERED_ON


def _get_vm_network_connections(vapp):
    connections = vapp.get_vms_network_info()[0]
    return filter(lambda network: network['is_connected'], connections)


def _get_vm_network_connection(vapp, network_name):
    connections = _get_vm_network_connections(vapp)
    for connection in connections:
        if connection['network_name'] == network_name:
            return connection


def _build_script(custom):
    script = custom.get('script')
    public_keys = custom.get('public_keys')
    if not script and not public_keys:
        return None
    script_executor = custom.get('script_executor', DEFAULT_EXECUTOR)
    configured_name = _create_file_name()

    commands = []
    commands.append("""#!{0}
    if [ -f /root/{1} ]; then
      exit
    fi
    touch /root/{1}
    """.format(script_executor, configured_name))
    ssh_dir_template = "{0}/{1}/.ssh"
    authorized_keys_template = "{0}/authorized_keys"
    add_key_template = "echo '{0}\n' >> {1}"
    test_ssh_dir_template = """
    if [ ! -d {1} ];then
      mkdir {1}
      chown {0}:{0} {1}
      chmod 700 {1}
      touch {2}
      chown {0}:{0} {2}
      chmod 600 {2}
    fi
    """
    for key in public_keys:
        public_key = key.get('key')
        if not public_key:
            continue
        user = key.get('user', DEFAULT_USER)
        home = key.get('home', DEFAULT_HOME)
        ssh_dir = ssh_dir_template.format(home, user)
        authorized_keys = authorized_keys_template.format(ssh_dir)
        test_ssh_dir = test_ssh_dir_template.format(user, ssh_dir, authorized_keys)
        commands.append(test_ssh_dir)
        commands.append(add_key_template.format(public_key, authorized_keys))
    if script:
        commands.append(script)
    script = "\n".join(commands)
    return script


def _create_file_name():
    chars = string.ascii_lowercase + string.digits
    configured_name = 'cloudify_confiured_{0}'.format(''.join([random.choice(chars)
                                                               for _ in range(5)]))
    return configured_name


def _create_connections_list(vca_client):
    connections = []
    ports = _get_connected(ctx.instance, 'port')
    networks = _get_connected(ctx.instance, 'network')

    management_network_name = ctx.node.properties.get('management_network')
    if not management_network_name:
        raise cfy_exc.NonRecoverableError("Parameter 'managment_network' for Server node is not defined.")

    if not is_network_exists(vca_client, management_network_name):
        raise cfy_exc.NonRecoverableError(
            "Network {0} could not be found".format(management_network_name))

    for port in ports:
        port_properties = port.node.properties['port']
        connections.append(_create_connection(port_properties['network'],
                                              port_properties.get('ip_address'),
                                              port_properties.get('mac_address'),
                                              port_properties.get('ip_allocation_mode',
                                                                  'DHCP').upper()))
    for net in networks:
        connections.append(_create_connection(get_network_name(net.node.properties),
                                              None, None, 'DHCP'))

    if not any([conn['network'] == management_network_name for conn in connections]):
        connections.append(_create_connection(management_network_name,
                                              None, None, 'DHCP'))
    for conn in connections:
        network_name = conn['network']
        if conn['ip_allocation_mode'] == 'DHCP' and not _isDhcpAvailable(vca_client, network_name):
            raise cfy_exc.NonRecoverableError("DHCP for network {0} is not available".format(network_name))
        conn['primary_interface'] = (network_name == management_network_name)
    return connections


def _get_connected(instance, prop):
    relationships = getattr(instance, 'relationships', None)
    if relationships:
        return [relationship.target for relationship in relationships
                if prop in relationship.target.node.properties]
    else:
        return []


def _create_connection(network, ip_address, mac_address, ip_allocation_mode):
    return {'network': network,
            'ip_address': ip_address,
            'mac_address': mac_address,
            'ip_allocation_mode': ip_allocation_mode}


def _isDhcpAvailable(vca_client, network_name):
    vdc = get_vcloud_config()['vdc']
    admin_href = vca_client.get_admin_network_href(vdc, network_name)
    for gate in vca_client.get_gateways(vdc):
        for pool in gate.get_dhcp_pools():
            if admin_href == pool.get_Network().get_href():
                return True
    return False
