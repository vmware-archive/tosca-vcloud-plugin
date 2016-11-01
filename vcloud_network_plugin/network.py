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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (with_vca_client, wait_for_task,
                                  get_vcloud_config, get_mandatory)
import collections
from vcloud_network_plugin import (check_ip, is_valid_ip_range, is_separate_ranges,
                                   is_ips_in_same_subnet, save_gateway_configuration,
                                   get_network_name, is_network_exists,
                                   get_gateway, set_retry)

VCLOUD_NETWORK_NAME = 'vcloud_network_name'
SKIP_CREATE_NETWORK = 'skip_create_network'
ADD_POOL = 1
DELETE_POOL = 2
CANT_DELETE = "cannot be deleted, because it is in use"


@operation
@with_vca_client
def create(vca_client, **kwargs):
    """
        create new vcloud air network, e.g.:
        {
            'use_external_resource': False,
            'resource_id': 'secret_network',
            'network': {
                'dhcp': {
                    'dhcp_range': "10.1.1.128-10.1.1.255"
                },
                'static_range':  "10.1.1.2-10.1.1.127",
                'gateway_ip': "10.1.1.1",
                'edge_gateway': 'gateway',
                'name': 'secret_network',
                "netmask": '255.255.255.0',
                "dns": ["8.8.8.8", "4.4.4.4"]
            }
        }
    """
    vdc_name = get_vcloud_config()['vdc']
    if ctx.node.properties['use_external_resource']:
        network_name = ctx.node.properties['resource_id']
        if not is_network_exists(vca_client, network_name):
            raise cfy_exc.NonRecoverableError(
                "Can't find external resource: {0}".format(network_name))
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = network_name
        ctx.logger.info(
            "External resource {0} has been used".format(network_name))
        return
    network_name = get_network_name(ctx.node.properties)
    if not ctx.instance.runtime_properties.get(SKIP_CREATE_NETWORK):
        net_prop = ctx.node.properties["network"]
        if network_name in _get_network_list(vca_client,
                                             get_vcloud_config()['vdc']):
            raise cfy_exc.NonRecoverableError(
                "Network {0} already exists, but parameter "
                "'use_external_resource' is 'false' or absent"
                .format(network_name))

        static_range = get_mandatory(net_prop, 'static_range') 
        ip = _split_adresses(static_range)
        gateway_name = net_prop['edge_gateway']
        get_gateway(vca_client, gateway_name)
        start_address = ip.start
        end_address = ip.end
        gateway_ip = net_prop["gateway_ip"]
        netmask = net_prop["netmask"]
        dns1 = ""
        dns2 = ""
        dns_list = net_prop.get("dns")
        if dns_list:
            dns1 = dns_list[0]
            if len(dns_list) > 1:
                dns2 = dns_list[1]
        dns_suffix = net_prop.get("dns_suffix")
        ctx.logger.info("Create network {0}."
                        .format(network_name))
        success, result = vca_client.create_vdc_network(
            vdc_name, network_name, gateway_name, start_address,
            end_address, gateway_ip, netmask, dns1, dns2, dns_suffix)
        if success:
            wait_for_task(vca_client, result)
            ctx.logger.info("Network {0} has been successfully created."
                            .format(network_name))
        else:
            raise cfy_exc.NonRecoverableError(
                "Could not create network {0}: {1}".
                format(network_name, result))
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = network_name
    if not _dhcp_operation(vca_client, network_name, ADD_POOL):
        ctx.instance.runtime_properties[SKIP_CREATE_NETWORK] = True
        return set_retry(ctx)


@operation
@with_vca_client
def delete(vca_client, **kwargs):
    """
        delete vcloud air network
    """
    if ctx.node.properties['use_external_resource'] is True:
        del ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        ctx.logger.info("Network was not deleted - external resource has"
                        " been used")
        return
    network_name = get_network_name(ctx.node.properties)
    if not _dhcp_operation(vca_client, network_name, DELETE_POOL):
        return set_retry(ctx)
    ctx.logger.info("Delete network '{0}'".format(network_name))
    success, task = vca_client.delete_vdc_network(
        get_vcloud_config()['vdc'], network_name)
    if success:
        wait_for_task(vca_client, task)
        ctx.logger.info(
            "Network '{0}' has been successful deleted.".format(network_name))
    else:
        if task and CANT_DELETE in task:
            ctx.logger.info("Network {} in use. Deleting the network skipped.".
                            format(network_name))
            return
        raise cfy_exc.NonRecoverableError(
            "Could not delete network '{0}': {1}".format(network_name, task))


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """
        check network description from node description
    """
    network_name = get_network_name(ctx.node.properties)
    ctx.logger.info("Validation cloudify.vcloud.nodes.Network node: {0}"
                    .format(network_name))
    if is_network_exists(vca_client, network_name):
        if ctx.node.properties.get('use_external_resource'):
            # TODO: check: default gateway must exists
            return
        else:
            raise cfy_exc.NonRecoverableError(
                "Network already exsists: {0}".format(network_name))

    net_prop = get_mandatory(ctx.node.properties, "network")
    gateway_name = get_mandatory(net_prop, 'edge_gateway')
    if not vca_client.get_gateway(get_vcloud_config()['vdc'], gateway_name):
        raise cfy_exc.NonRecoverableError(
            "Gateway {0} not found".format(gateway_name))

    static_ip = _split_adresses(get_mandatory(net_prop, 'static_range'))
    check_ip(static_ip.start)
    check_ip(static_ip.end)
    dns_list = net_prop.get("dns")
    if dns_list:
        for ip in dns_list:
            check_ip(ip)
    gateway_ip = check_ip(get_mandatory(net_prop, "gateway_ip"))
    netmask = check_ip(get_mandatory(net_prop, "netmask"))

    ips = [gateway_ip, static_ip.start, static_ip.end]
    dhcp = net_prop.get("dhcp")
    if dhcp:
        dhcp_range = get_mandatory(net_prop["dhcp"], "dhcp_range")
        dhcp_ip = _split_adresses(dhcp_range)
        if not is_separate_ranges(static_ip, dhcp_ip):
            raise cfy_exc.NonRecoverableError(
                "Static_range and dhcp_range is overlapped.")
        ips.extend([dhcp_ip.start, dhcp_ip.end])
    if not is_ips_in_same_subnet(ips, netmask):
            raise cfy_exc.NonRecoverableError(
                "IP addresses in different subnets.")


def _dhcp_operation(vca_client, network_name, operation):
    """
        update dhcp setting for network
    """
    dhcp_settings = ctx.node.properties['network'].get('dhcp')
    if dhcp_settings is None:
        return True
    gateway_name = ctx.node.properties["network"]['edge_gateway']
    gateway = get_gateway(vca_client, gateway_name)
    if gateway.is_busy():
        return False
    if operation == ADD_POOL:
        ip = _split_adresses(dhcp_settings['dhcp_range'])
        low_ip_address = check_ip(ip.start)
        hight_ip_address = check_ip(ip.end)
        default_lease = dhcp_settings.get('default_lease')
        max_lease = dhcp_settings.get('max_lease')
        gateway.add_dhcp_pool(network_name, low_ip_address, hight_ip_address,
                              default_lease, max_lease)
        if save_gateway_configuration(gateway, vca_client, ctx):
            ctx.logger.info("DHCP rule successful created for network {0}"
                            .format(network_name))
            return True

    if operation == DELETE_POOL:
        gateway.delete_dhcp_pool(network_name)
        if save_gateway_configuration(gateway, vca_client, ctx):
            ctx.logger.info("DHCP rule successful deleted for network {0}"
                            .format(network_name))
            return True
    return False


def _split_adresses(address_range):
    """
        split network addresses from 1.1.1.1-2.2.2.2 representation to
        separate (start,end) tuple
    """
    adresses = [ip.strip() for ip in address_range.split('-')]
    IPRange = collections.namedtuple('IPRange', 'start end')
    try:
        start = check_ip(adresses[0])
        end = check_ip(adresses[1])
        if not is_valid_ip_range(start, end):
            raise cfy_exc.NonRecoverableError(
                "Start address {0} is greater than end address: {1}"
                .format(start, end))
        return IPRange(start=start, end=end)
    except IndexError:
        raise cfy_exc.NonRecoverableError("Can't parse IP range:{0}".
                                          format(address_range))


def _get_network_list(vca_client, vdc_name):
    """
        list all avable network for current vdc
    """
    vdc = vca_client.get_vdc(vdc_name)
    if not vdc:
        raise cfy_exc.NonRecoverableError(
            "Vdc {0} not found.".format(vdc_name))
    return [net.name for net in vdc.AvailableNetworks.Network]
