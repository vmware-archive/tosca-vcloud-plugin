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

from vcloud_plugin_common import (get_vcloud_config,
                                  transform_resource_name,
                                  wait_for_task,
                                  with_vca_client,
                                  STATUS_POWERED_ON)

from network_plugin import (get_network_name, get_network, is_network_exists,
                            get_vapp_name)

VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
GUEST_CUSTOMIZATION = 'guest_customization'
HARDWARE = 'hardware'
DEFAULT_EXECUTOR = "/bin/bash"
DEFAULT_USER = "ubuntu"
DEFAULT_HOME = "/home"


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    def get_catalog(catalog_name):
        catalogs = vca_client.get_catalogs()
        for catalog in catalogs:
            if catalog.get_name() == catalog_name:
                return catalog

    def get_template(catalog, template_name):
        for template in catalog.get_CatalogItems().get_CatalogItem():
            if template.get_name() == template_name:
                return template

    if ctx.node.properties.get('use_external_resource'):
        if not ctx.node.properties.get('resource_id'):
            raise cfy_exc.NonRecoverableError(
                "resource_id server properties must be specified"
            )
        return

    server_dict = ctx.node.properties['server']
    required_params = ('catalog', 'template')
    missed_params = set(required_params) - set(server_dict.keys())
    if len(missed_params) > 0:
        raise cfy_exc.NonRecoverableError(
            "{0} server properties must be specified"
            .format(list(missed_params)))

    catalog = get_catalog(server_dict['catalog'])
    if catalog is None:
        raise cfy_exc.NonRecoverableError(
            "Catalog {0} could not be found".format(server_dict['catalog']))

    template = get_template(catalog, server_dict['template'])
    if template is None:
        raise cfy_exc.NonRecoverableError(
            "Template {0} could not be found".format(server_dict['template']))


@operation
@with_vca_client
def create(vca_client, **kwargs):
    config = get_vcloud_config()
    server = {
        'name': ctx.instance.id,
    }
    server.update(ctx.node.properties.get('server', {}))
    transform_resource_name(server, ctx)

    if ctx.node.properties.get('use_external_resource'):
        res_id = ctx.node.properties['resource_id']
        ctx.instance.runtime_properties[VCLOUD_VAPP_NAME] = res_id
        ctx.logger.info(
            "External resource {0} has been used".format(res_id))
    else:
        _create(vca_client, config, server)


def _create(vca_client, config, server):
    vapp_name = server['name']
    vapp_template = server['template']
    vapp_catalog = server['catalog']
    hardware = server.get('hardware')
    cpu = None
    memory = None
    if hardware:
        cpu = hardware.get('cpu')
        memory = hardware.get('memory')
        _check_hardware(cpu, memory)
    ctx.logger.info("Creating VApp with parameters: {0}".format(str(server)))
    task = vca_client.create_vapp(config['vdc'],
                                  vapp_name,
                                  vapp_template,
                                  vapp_catalog,
                                  vm_name=vapp_name,
                                  vm_cpus=cpu,
                                  vm_memory=memory)

    if not task:
        raise cfy_exc.NonRecoverableError("Could not create vApp: {0}"
                                          .format(vca_client.response.content))

    wait_for_task(vca_client, task)
    ctx.instance.runtime_properties[VCLOUD_VAPP_NAME] = vapp_name
    connections = _create_connections_list(vca_client)

    # we allways have connection to management_network_name
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
                                                'POOL').upper()
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
    if ctx.node.properties.get('use_external_resource'):
        ctx.logger.info('not starting server since an external server is '
                        'being used')
    else:
        vapp_name = get_vapp_name(ctx.instance.runtime_properties)
        config = get_vcloud_config()
        vdc = vca_client.get_vdc(config['vdc'])
        vapp = vca_client.get_vapp(vdc, vapp_name)
        if _vapp_is_on(vapp) is False:
            ctx.logger.info("Power-on VApp {0}".format(vapp_name))
            task = vapp.poweron()
            if not task:
                raise cfy_exc.NonRecoverableError("Could not power-on vApp")
            wait_for_task(vca_client, task)

    if not _get_state(vca_client):
        return ctx.operation.retry(
            message="Waiting for VM's configuration to complete",
            retry_after=5)


@operation
@with_vca_client
def stop(vca_client, **kwargs):
    if ctx.node.properties.get('use_external_resource'):
        ctx.logger.info('not stopping server since an external server is '
                        'being used')
    else:
        vapp_name = get_vapp_name(ctx.instance.runtime_properties)
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
    if ctx.node.properties.get('use_external_resource'):
        ctx.logger.info('not deleting server since an external server is '
                        'being used')
    else:
        vapp_name = get_vapp_name(ctx.instance.runtime_properties)
        config = get_vcloud_config()
        vdc = vca_client.get_vdc(config['vdc'])
        vapp = vca_client.get_vapp(vdc, vapp_name)
        ctx.logger.info("Deleting VApp {0}".format(vapp_name))
        task = vapp.delete()
        if not task:
            raise cfy_exc.NonRecoverableError("Could not delete vApp")
        wait_for_task(vca_client, task)

    del ctx.instance.runtime_properties[VCLOUD_VAPP_NAME]


def _get_management_network_from_node():
    management_network_name = ctx.node.properties.get('management_network')
    if not management_network_name:
        resources = ctx.provider_context.get('resources')
        if resources and 'int_network' in resources:
            management_network_name = resources['int_network'].get('name')
    if not management_network_name:
        raise cfy_exc.NonRecoverableError(
            "Parameter 'managment_network' for Server node is not defined.")
    return management_network_name


def _get_state(vca_client):
    vapp_name = get_vapp_name(ctx.instance.runtime_properties)
    config = get_vcloud_config()
    vdc = vca_client.get_vdc(config['vdc'])
    vapp = vca_client.get_vapp(vdc, vapp_name)
    nw_connections = _get_vm_network_connections(vapp)
    if len(nw_connections) == 0:
        ctx.logger.info("No networks connected")
        ctx.instance.runtime_properties['ip'] = None
        ctx.instance.runtime_properties['networks'] = {}
        return True
    management_network_name = _get_management_network_from_node()

    if not all([connection['ip'] for connection in nw_connections]):
        ctx.logger.info("Network configuration is not finished yet.")
        return False

    ctx.instance.runtime_properties['networks'] = {
        connection['network_name']: connection['ip']
        for connection in nw_connections}

    for connection in nw_connections:
        if connection['network_name'] == management_network_name:
            ctx.logger.info("Management network ip address {0}"
                            .format(connection['ip']))
            ctx.instance.runtime_properties['ip'] = connection['ip']
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
    pre_script = custom.get('pre_script', "")
    post_script = custom.get('post_script', "")
    public_keys = custom.get('public_keys')
    if not pre_script and not post_script and not public_keys:
        return None
    script_executor = custom.get('script_executor', DEFAULT_EXECUTOR)
    public_keys_script = _build_public_keys_script(public_keys)
    script_template = """#!{0}
echo performing customization tasks with param $1 \
at `date "+DATE: %Y-%m-%d - TIME: %H:%M:%S"` >> /root/customization.log
if [ "$1" = "precustomization" ];
then
  echo performing precustomization tasks \
  on `date "+DATE: %Y-%m-%d - TIME: %H:%M:%S"` >> /root/customization.log
  {1}
  {2}
fi
if [ "$1" = "postcustomization" ];
then
  echo performing postcustomization tasks \
  at `date "+DATE: %Y-%m-%d - TIME: %H:%M:%S"` >> /root/customization.log
  {3}
fi
    """
    script = script_template.format(script_executor, public_keys_script,
                                    pre_script, post_script)
    return script


def _build_public_keys_script(public_keys):
    key_commands = []
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
        test_ssh_dir = test_ssh_dir_template.format(
            user, ssh_dir, authorized_keys)
        key_commands.append(test_ssh_dir)
        key_commands.append(
            add_key_template.format(public_key, authorized_keys))
    return "\n".join(key_commands)


def _create_connections_list(vca_client):
    connections = []
    ports = _get_connected(ctx.instance, 'port')
    networks = _get_connected(ctx.instance, 'network')

    management_network_name = _get_management_network_from_node()

    if not is_network_exists(vca_client, management_network_name):
        raise cfy_exc.NonRecoverableError(
            "Network {0} could not be found".format(management_network_name))

    for port in ports:
        port_properties = port.node.properties['port']
        connections.append(
            _create_connection(port_properties['network'],
                               port_properties.get('ip_address'),
                               port_properties.get('mac_address'),
                               port_properties.get('ip_allocation_mode',
                                                   'POOL').upper(),
                               port_properties.get('primary_interface', False))
        )
    for net in networks:
        connections.append(
            _create_connection(get_network_name(net.node.properties),
                               None, None, 'POOL'))

    if not any([conn['network'] == management_network_name
                for conn in connections]):
        connections.append(_create_connection(management_network_name,
                                              None, None, 'POOL'))

    primary_iface_set = len(filter(lambda conn: conn.get('primary_interface',
                                                         False),
                                   connections)) > 0

    for conn in connections:
        network_name = conn['network']
        if (conn['ip_allocation_mode'] == 'DHCP'
                and not _isDhcpAvailable(vca_client, network_name)):
            raise cfy_exc.NonRecoverableError(
                "DHCP for network {0} is not available"
                .format(network_name))

        if primary_iface_set is False:
            conn['primary_interface'] = \
                (network_name == management_network_name)

    return connections


def _get_connected(instance, prop):
    relationships = getattr(instance, 'relationships', None)
    if relationships:
        return [relationship.target for relationship in relationships
                if prop in relationship.target.node.properties]
    else:
        return []


def _create_connection(network, ip_address, mac_address, ip_allocation_mode,
                       primary_interface=False):
    return {'network': network,
            'ip_address': ip_address,
            'mac_address': mac_address,
            'ip_allocation_mode': ip_allocation_mode,
            'primary_interface': primary_interface}


def _isDhcpAvailable(vca_client, network_name):
    vdc_name = get_vcloud_config()['vdc']
    network = vca_client.get_network(vdc_name, network_name)
    if network.get_Configuration().get_FenceMode() == "bridged":
        # NOTE(nmishkin) Can't tell whether bridged networks have DHCP
        # so just hope for the best
        return True
    # TODO: Why not just get the gateway directly from the network?
    admin_href = vca_client.get_admin_network_href(vdc_name, network_name)
    for gate in vca_client.get_gateways(vdc_name):
        for pool in gate.get_dhcp_pools():
            if admin_href == pool.get_Network().get_href():
                return True
    return False


def _check_hardware(cpu, memory):
    if cpu is not None:
        if isinstance(cpu, int):
            if cpu < 1:
                raise cfy_exc.NonRecoverableError(
                    "Too small quantity of CPU's: {0}".format(cpu))
            if cpu > 64:
                raise cfy_exc.NonRecoverableError(
                    "Too many of CPU's: {0}".format(cpu))
        else:
            raise cfy_exc.NonRecoverableError(
                "Quantity of CPU's must be integer")

    if memory is not None:
        if isinstance(memory, int):
            if memory < 512:
                raise cfy_exc.NonRecoverableError(
                    "Too small quantity of memory: {0}".format(memory))
            if memory > (512 * 1024):  # 512Gb
                raise cfy_exc.NonRecoverableError(
                    "Too many memory: {0}".format(memory))
        else:
            raise cfy_exc.NonRecoverableError(
                "Quantity of memory must be integer")
