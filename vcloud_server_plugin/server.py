# Copyright (c) 2014-2020 Cloudify Platform Ltd. All rights reserved
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

import time

from cloudify.decorators import operation
from cloudify import exceptions as cfy_exc

from vcloud_plugin_common import (get_vcloud_config,
                                  transform_resource_name,
                                  wait_for_task,
                                  with_vca_client,
                                  error_response,
                                  combine_properties,
                                  delete_properties,
                                  STATUS_POWERED_ON)
from vcloud_network_plugin import (get_network_name, get_network,
                                   is_network_exists,
                                   get_vapp_name, GATEWAY_TIMEOUT, RETRY_COUNT)
from vcloud_network_plugin.keypair import PUBLIC_KEY, SSH_KEY

VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
GUEST_CUSTOMIZATION = 'guest_customization'
HARDWARE = 'hardware'
DEFAULT_EXECUTOR = "/bin/bash"
DEFAULT_USER = "ubuntu"
DEFAULT_HOME = "/home"


@operation(resumable=True)
@with_vca_client
def creation_validation(ctx, vca_client, **kwargs):
    """
        validate server settings, look to template in catalog
    """
    def get_catalog(catalog_name):
        catalogs = vca_client.get_catalogs()
        for catalog in catalogs:
            if catalog.get_name() == catalog_name:
                return catalog

    def get_template(catalog, template_name):
        for template in catalog.get_CatalogItems().get_CatalogItem():
            if template.get_name() == template_name:
                return template

    # combine properties
    obj = combine_properties(
        ctx, kwargs=kwargs, names=['server'],
        properties=[VCLOUD_VAPP_NAME, 'management_network'])
    # get external
    if obj.get('use_external_resource'):
        if not obj.get('resource_id'):
            raise cfy_exc.NonRecoverableError(
                "resource_id server properties must be specified"
            )
        return

    server_dict = obj['server']
    required_params = ('catalog', 'template')
    missed_params = set(required_params) - set(server_dict.keys())
    if len(missed_params) > 0:
        raise cfy_exc.NonRecoverableError(
            "{0} server properties must be specified"
            .format(list(missed_params)))

    catalog = get_catalog(server_dict['catalog'])
    if catalog is None:
        raise cfy_exc.NonRecoverableError(
            "Catalog '{0}' could not be found".format(server_dict['catalog']))

    template = get_template(catalog, server_dict['template'])
    if template is None:
        raise cfy_exc.NonRecoverableError(
            "Template '{0}' could not be found".
            format(server_dict['template']))


@operation(resumable=True)
@with_vca_client
def create(ctx, vca_client, **kwargs):
    """
        create server by template,
        if external_resource set return without creation,
        e.g.:
        {
            'management_network': '_management_network',
            'server': {
                'template': 'template',
                'catalog': 'catalog',
                'guest_customization': {
                    'pre_script': 'pre_script',
                    'post_script': 'post_script',
                    'admin_password': 'pass',
                    'computer_name': 'computer'

                }
            }
        }
    """
    config = get_vcloud_config()
    server = {
        'name': ctx.instance.id,
    }
    # combine properties
    obj = combine_properties(
        ctx, kwargs=kwargs, names=['server'],
        properties=[VCLOUD_VAPP_NAME, 'management_network'])
    server.update(obj.get('server', {}))
    transform_resource_name(server, ctx)
    # get external
    if obj.get('use_external_resource'):
        res_id = obj['resource_id']
        ctx.instance.runtime_properties[VCLOUD_VAPP_NAME] = res_id
        vdc = vca_client.get_vdc(config['vdc'])
        if not vca_client.get_vapp(vdc, res_id):
            raise cfy_exc.NonRecoverableError(
                "Unable to find external vAPP server resource {0}."
                .format(res_id))
        server.update({'name': res_id})
        ctx.logger.info(
            "External resource {0} has been used".format(res_id))
    else:
        _create(ctx, vca_client, config, server)


def _create(ctx, vca_client, config, server):
    """
        create server by template,
        customize:
         * hardware: memmory/cpu
         * software: root password, computer internal hostname
         connect vm to network
    """
    vapp_name = server['name']
    vapp_template = server['template']
    vapp_catalog = server['catalog']
    connections = _create_connections_list(ctx, vca_client)
    ctx.logger.info("Creating VApp with parameters: {0}".format(server))
    task = vca_client.create_vapp(config['vdc'],
                                  vapp_name,
                                  vapp_template,
                                  vapp_catalog)
    if not task:
        raise cfy_exc.NonRecoverableError("Could not create vApp: {0}"
                                          .format(error_response(vca_client)))
    wait_for_task(vca_client, task)

    vdc = vca_client.get_vdc(config['vdc'])
    vapp = vca_client.get_vapp(vdc, vapp_name)
    if vapp is None:
        raise cfy_exc.NonRecoverableError(
            "vApp '{0}' could not be found".format(vapp_name))

    task = vapp.modify_vm_name(1, vapp_name)
    if not task:
        raise cfy_exc.NonRecoverableError(
            "Can't modyfy VM name: {0}".format(vapp_name))
    wait_for_task(vca_client, task)
    ctx.logger.info("VM '{0}' has been renamed.".format(vapp_name))

    # reread vapp
    vapp = vca_client.get_vapp(vdc, vapp_name)
    ctx.instance.runtime_properties[VCLOUD_VAPP_NAME] = vapp_name

    # we allways have connection to management_network_name
    if connections:
        for index, connection in enumerate(connections):
            network_name = connection.get('network')
            network = get_network(vca_client, network_name)
            ctx.logger.info("Connect network '{0}' to server '{1}'."
                            .format(network_name, vapp_name))
            task = vapp.connect_to_network(network_name, network.get_href())
            if not task:
                raise cfy_exc.NonRecoverableError(
                    "Could not add network {0} to VApp {1}. {2}"
                    .format(network_name, vapp_name, error_response(vapp)))
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
                    "Could not connect vApp {0} to network {1}. {2}"
                    .format(vapp_name, network_name, error_response(vapp)))
            wait_for_task(vca_client, task)


def _power_on_vm(ctx, vca_client, vapp, vapp_name):
    """Poweron VM"""
    if _vapp_is_on(vapp) is False:
        ctx.logger.info("Power-on VApp {0}".format(vapp_name))
        task = vapp.poweron()
        if not task:
            raise cfy_exc.NonRecoverableError(
                "Could not power-on vApp. {0}".
                format(error_response(vapp)))
        wait_for_task(vca_client, task)


@operation(resumable=True)
@with_vca_client
def start(ctx, vca_client, **kwargs):
    """
    power on server and wait network connection availability for host
    """
    # combine properties
    obj = combine_properties(
        ctx, kwargs=kwargs, names=['server'],
        properties=[VCLOUD_VAPP_NAME, 'management_network'])
    # get external
    if obj.get('use_external_resource'):
        ctx.logger.info('not starting server since an external server is '
                        'being used')
    else:
        vapp_name = get_vapp_name(ctx.instance.runtime_properties)
        config = get_vcloud_config()
        vdc = vca_client.get_vdc(config['vdc'])
        vapp = vca_client.get_vapp(vdc, vapp_name)
        _power_on_vm(ctx, vca_client, vapp, vapp_name)

    if not _get_state(ctx=ctx, vca_client=vca_client):
        return ctx.operation.retry(
            message="Waiting for VM's configuration to complete",
            retry_after=5)


@operation(resumable=True)
@with_vca_client
def stop(ctx, vca_client, **kwargs):
    """
        poweroff server, if external resource - server stay poweroned
    """
    # combine properties
    obj = combine_properties(
        ctx, kwargs=kwargs, names=['server'],
        properties=[VCLOUD_VAPP_NAME, 'management_network'])
    # get external
    if obj.get('use_external_resource'):
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
            raise cfy_exc.NonRecoverableError("Could not undeploy vApp {0}".
                                              format(error_response(vapp)))
        wait_for_task(vca_client, task)


@operation(resumable=True)
@with_vca_client
def delete(ctx, vca_client, **kwargs):
    """
        delete server
    """
    # combine properties
    obj = combine_properties(
        ctx, kwargs=kwargs, names=['server'],
        properties=[VCLOUD_VAPP_NAME, 'management_network'])
    # get external
    if obj.get('use_external_resource'):
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
            raise cfy_exc.NonRecoverableError("Could not delete vApp {0}".
                                              format(error_response(vapp)))
        wait_for_task(vca_client, task)

    delete_properties(ctx)


def _is_primary_connection_has_ip(vapp):
    """Return True in case when primary interface has some ip"""
    network_info = vapp.get_vms_network_info()
    # we dont have any network, skip checks
    if not network_info:
        return True
    if not network_info[0]:
        return True
    # we have some networks
    for conn in network_info[0]:
        if conn['is_connected'] and conn['is_primary'] and conn['ip']:
            return True
    return False


@operation(resumable=True)
@with_vca_client
def configure(ctx, vca_client, **kwargs):
    # combine properties
    obj = combine_properties(
        ctx, kwargs=kwargs, names=['server'],
        properties=[VCLOUD_VAPP_NAME, 'management_network'])
    # get external
    if obj.get('use_external_resource'):
        ctx.logger.info('Avoiding external resource configuration.')
    else:
        ctx.logger.info("Configure server")
        server = {'name': ctx.instance.id}
        server.update(ctx.node.properties.get('server', {}))
        server.update(kwargs.get('server', {}))
        ctx.logger.info("Server properties: {0}"
                        .format(str(server)))
        vapp_name = server['name']
        config = get_vcloud_config()
        custom = server.get(GUEST_CUSTOMIZATION, {})
        public_keys = _get_connected_keypairs(ctx)

        vdc = vca_client.get_vdc(config['vdc'])
        vapp = vca_client.get_vapp(vdc, vapp_name)
        if not vapp:
            raise cfy_exc.NonRecoverableError(
                "Unable to find vAPP server "
                "by its name {0}.".format(vapp_name))
        ctx.logger.info("Using vAPP {0}".format(str(vapp_name)))

        hardware = server.get('hardware')
        if hardware:
            cpu = hardware.get('cpu')
            memory = hardware.get('memory')
            _check_hardware(cpu, memory)
            if memory:
                try:
                    ctx.logger.info(
                        "Customize VM memory: '{0}'.".format(memory)
                    )
                    task = vapp.modify_vm_memory(vapp_name, memory)
                    wait_for_task(vca_client, task)
                except Exception:
                    raise cfy_exc.NonRecoverableError(
                        "Customize VM memory failed: '{0}'. {1}".
                        format(task, error_response(vapp)))
            if cpu:
                try:
                    ctx.logger.info(
                        "Customize VM cpu: '{0}'.".format(cpu)
                    )
                    task = vapp.modify_vm_cpu(vapp_name, cpu)
                    wait_for_task(vca_client, task)
                except Exception:
                    raise cfy_exc.NonRecoverableError(
                        "Customize VM cpu failed: '{0}'. {1}".
                        format(task, error_response(vapp)))

        if custom or public_keys:
            script = _build_script(custom, public_keys)
            password = custom.get('admin_password')
            computer_name = custom.get('computer_name')
            ctx.logger.info("Customizing guest OS.")
            task = vapp.customize_guest_os(
                vapp_name,
                customization_script=script,
                computer_name=computer_name,
                admin_password=password
            )
            ctx.logger.debug(
                "VM {vapp_name} Customized with sript:\n{script}\n"
                "computer_name:\n{computer_name}\n"
                "password:\n{password}\n".format(
                    vapp_name=vapp_name,
                    script=script,
                    computer_name=computer_name,
                    password=password))
            if task is None:
                raise cfy_exc.NonRecoverableError(
                    "Could not set guest customization parameters. {0}".
                    format(error_response(vapp)))
            wait_for_task(vca_client, task)
            if vapp.customize_on_next_poweron():
                ctx.logger.info("Customizations successful")
            else:
                customization_task = vapp.force_customization(vapp_name)
                if customization_task:
                    ctx.logger.info("Customizations forced")
                    wait_for_task(vca_client, customization_task)
                else:
                    raise cfy_exc.NonRecoverableError(
                        "Can't run customization in next power on. {0}".
                        format(error_response(vapp)))

        if not _is_primary_connection_has_ip(vapp):
            ctx.logger.info("Power on server for get dhcp ip.")
            # we have to start vapp before continue
            _power_on_vm(ctx, vca_client, vapp, vapp_name)
            for attempt in xrange(RETRY_COUNT):
                vapp = vca_client.get_vapp(vdc, vapp_name)
                if _is_primary_connection_has_ip(vapp):
                    return
                ctx.logger.info(
                    "No ip assigned. Retrying... {}/{} attempt."
                    .format(attempt + 1, RETRY_COUNT)
                )
                time.sleep(GATEWAY_TIMEOUT)
            ctx.logger.info("We dont recieve ip, try next time...")


@operation(resumable=True)
@with_vca_client
def remove_keys(ctx, vca_client, **kwargs):
    ctx.logger.info("Remove public keys from VM.")
    relationships = getattr(ctx.target.instance, 'relationships', None)
    if relationships:
        public_keys = [
            relationship.target.instance.runtime_properties['public_key']
            for relationship in relationships
            if 'public_key' in
            relationship.target.instance.runtime_properties
        ]
    else:
        return
    vdc = vca_client.get_vdc(get_vcloud_config()['vdc'])
    vapp_name = ctx.target.instance.id
    vapp = vca_client.get_vapp(vdc, vapp_name)
    if not vapp:
        vapp_name = ctx.target.node.properties['server'].get('name', '')
        vapp = vca_client.get_vapp(vdc, vapp_name)
        if not vapp:
            raise cfy_exc.NonRecoverableError(
                "Unable to find vAPP server "
                "by its name {0}.".format(vapp_name))
    ctx.logger.info("Using vAPP {0}".format(str(vapp_name)))
    script = "#!/bin/sh\n" + _build_public_keys_script(public_keys,
                                                       _remove_key_script)
    task = vapp.undeploy()
    if not task:
        raise cfy_exc.NonRecoverableError(
            "Can't power off VM. {0}".format(vapp_name))
    wait_for_task(vca_client, task)
    task = vapp.customize_guest_os(
        vapp_name,
        customization_script=script)
    if not task:
        raise cfy_exc.NonRecoverableError(
            "Could not set guest customization parameters. {0}.".
            format(error_response(vapp)))
    wait_for_task(vca_client, task)
    if vapp.customize_on_next_poweron():
        ctx.logger.info("Customizations successful.")
    else:
        customization_task = vapp.force_customization(vapp_name)
        if customization_task:
            ctx.logger.info("Customizations forced")
            wait_for_task(vca_client, customization_task)
        else:
            raise cfy_exc.NonRecoverableError(
                "Can't run customization on next power on. {0}.".
                format(error_response(vapp)))
    vapp = vca_client.get_vapp(vdc, vapp_name)
    task = vapp.poweron()
    if not task:
        raise cfy_exc.NonRecoverableError(
            "Can't poweron VM. {0}".format(vapp_name))
    wait_for_task(vca_client, task)
    ctx.logger.info("Power on after deleting public key successful.")

    ctx.logger.info("Remove keys from properties.")
    host_rt_properties = ctx.target.instance.runtime_properties
    if SSH_KEY in host_rt_properties:
        del host_rt_properties[SSH_KEY]


def _remove_key_script(commands, user, ssh_dir, keys_file, public_key):
    sed_template = " sed -i /{0}/d {1}"
    commands.append(sed_template.format(
        public_key.split()[1].replace('/', '[/]'), keys_file)
    )


def _get_state(ctx, vca_client):
    """
        check network connection availability for host
    """
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

    if not all([connection['ip'] for connection in nw_connections]):
        ctx.logger.info("Network configuration is not finished yet.")
        return False

    ctx.instance.runtime_properties['networks'] = {
        connection['network_name']: connection['ip']
        for connection in nw_connections}

    for connection in nw_connections:
        if connection['is_primary']:
            ctx.logger.info("Primary network ip address '{0}' for"
                            "  network '{1}'."
                            .format(connection['ip'],
                                    connection['network_name']))
            ctx.instance.runtime_properties['ip'] = connection['ip']
            return True
    return False


def _vapp_is_on(vapp):
    """
        server is on
    """
    return vapp.me.get_status() == STATUS_POWERED_ON


def _get_vm_network_connections(vapp):
    """
        get list connected networlks
    """
    connections = vapp.get_vms_network_info()[0]
    return filter(lambda network: network['is_connected'], connections)


def _get_vm_network_connection(vapp, network_name):
    """
        return network connection by name
    """
    connections = _get_vm_network_connections(vapp)
    for connection in connections:
        if connection['network_name'] == network_name:
            return connection


def _build_script(custom, public_keys):
    """
        create customization script
    """
    pre_script = custom.get('pre_script', "")
    post_script = custom.get('post_script', "")
    if not pre_script and not post_script and not public_keys:
        return None
    script_executor = DEFAULT_EXECUTOR
    public_keys_script = _build_public_keys_script(public_keys,
                                                   _add_key_script)
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


def _get_connected_keypairs(ctx):
    """
        return public keys connected to node
    """
    relationships = getattr(ctx.instance, 'relationships', None)
    if relationships:
        return [relationship.target.instance.runtime_properties[PUBLIC_KEY]
                for relationship in relationships
                if PUBLIC_KEY in
                relationship.target.instance.runtime_properties]
    else:
        return []


def _add_key_script(commands, user, ssh_dir, keys_file, public_key):
    """
        return commands for inject public key to node
    """
    add_key_template = "echo '{0}\n' >> {1}"
    test_ssh_dir_template = """
    if [ ! -d {1} ];then
      mkdir {1}
      chown {0}:{0} {1}
      chmod 700 {1}
      touch {2}
      chown {0}:{0} {2}
      chmod 600 {2}
      # make centos with selinux happy
      which restorecon && restorecon -Rv {1}
    fi
    """
    test_ssh_dir = test_ssh_dir_template.format(user, ssh_dir, keys_file)
    commands.append(test_ssh_dir)
    commands.append(add_key_template.format(public_key, keys_file))


def _build_public_keys_script(public_keys, script_function):
    """
        create script for update ssh keys
    """
    key_commands = []
    ssh_dir_template = "{0}/{1}/.ssh"
    authorized_keys_template = "{0}/authorized_keys"
    for key in public_keys:
        public_key = key.get('key')
        if not public_key:
            continue
        user = key.get('user')
        if not user:
            user = DEFAULT_USER
        home = key.get('home')
        if not home:
            home = '' if user == 'root' else DEFAULT_HOME
        ssh_dir = ssh_dir_template.format(home, user)
        authorized_keys = authorized_keys_template.format(ssh_dir)
        script_function(
            key_commands, user, ssh_dir, authorized_keys, public_key
        )
    return "\n".join(key_commands)


def _create_connections_list(ctx, vca_client):
    """
        return full list connections for node
    """
    connections = []
    ports = _get_connected(ctx.instance, 'port')
    networks = _get_connected(ctx.instance, 'network')

    management_network_name = ctx.node.properties.get('management_network')

    for port in ports:
        obj = combine_properties(port, names=['port'])
        port_properties = obj['port']
        connections.append(
            _create_connection(port_properties['network'],
                               port_properties.get('ip_address'),
                               port_properties.get('mac_address'),
                               port_properties.get('ip_allocation_mode',
                                                   'POOL').upper(),
                               port_properties.get('primary_interface', False),
                               port_properties.get('nic_order', 0))
        )

    for net in networks:
        obj = combine_properties(net, names=['network'])
        connections.append(
            _create_connection(get_network_name(net.node.properties),
                               None, None, 'POOL'))

    if management_network_name and not any(
            [conn['network'] == management_network_name
             for conn in connections]):
        connections.append(_create_connection(management_network_name,
                                              None, None, 'POOL'))

    for conn in connections:
        if not is_network_exists(vca_client, conn['network']):
            raise cfy_exc.NonRecoverableError(
                "Network '{0}' could not be found".format(conn['network']))

    primary_iface_set = len(filter(lambda conn: conn.get('primary_interface',
                                                         False),
                                   connections)) > 0
    if not primary_iface_set:
        if management_network_name:
            primary_name = management_network_name
        elif connections:
            primary_name = connections[0]['network']
        else:
            raise cfy_exc.NonRecoverableError(
                "Can't setup primary interface")

    # check list of connections and set managment network as primary
    # in case when we dont have any primary networks
    for conn in connections:
        network_name = conn['network']
        if (conn['ip_allocation_mode'] == 'DHCP' and not _isDhcpAvailable(
            vca_client, network_name
        )):
            ctx.logger.warning(
                "DHCP for network {0} is not available"
                .format(network_name))
        if not primary_iface_set:
            conn['primary_interface'] = \
                (network_name == primary_name)
        if conn['primary_interface']:
            ctx.logger.info(
                "The primary interface has been set to {}".format(
                    network_name))

    return sorted(connections, key=lambda k: k['nic_order'])


def _get_connected(instance, prop):
    """
        get property from instance relationships
    """
    relationships = getattr(instance, 'relationships', None)
    if relationships:
        return [relationship.target for relationship in relationships
                if prop in relationship.target.node.properties]
    else:
        return []


def _create_connection(network, ip_address, mac_address, ip_allocation_mode,
                       primary_interface=False, nic_order=0):
    """
        repack fields to dict
    """
    return {'network': network,
            'ip_address': ip_address,
            'mac_address': mac_address,
            'ip_allocation_mode': ip_allocation_mode,
            'primary_interface': primary_interface,
            'nic_order': nic_order}


def _isDhcpAvailable(vca_client, network_name):
    """
        check dhcp availability for network
    """
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
    """
        check hardware setting
            1 <= cpu <= 64
            512M <= memmory <= 512G
    """
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
