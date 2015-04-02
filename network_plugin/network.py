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
from vcloud_plugin_common import (with_vca_client, wait_for_task,
                                  get_vcloud_config, get_mandatory)
import collections
from network_plugin import (check_ip, is_valid_ip_range, is_separate_ranges,
                            is_ips_in_same_subnet, save_gateway_configuration,
                            get_network_name, is_network_exists)


VCLOUD_NETWORK_NAME = 'vcloud_network_name'
ADD_POOL = 1
DELETE_POOL = 2


@operation
@with_vca_client
def create(vca_client, **kwargs):
    org_name = get_vcloud_config()['org']
    if ctx.node.properties['use_external_resource']:
        network_name = ctx.node.properties['resource_id']
        if not is_network_exists(vca_client, network_name):
            raise cfy_exc.NonRecoverableError(
                "Can't find external resource: {0}".format(network_name))
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = network_name
        ctx.logger.info(
            "External resource {0} has been used".format(network_name))
        return
    net_prop = ctx.node.properties["network"]
    network_name = get_network_name(ctx.node.properties)
    if network_name in _get_network_list(vca_client,
                                         get_vcloud_config()['org']):
        raise cfy_exc.NonRecoverableError(
            "Network {0} already exists, but parameter "
            "'use_external_resource' is 'false' or absent"
            .format(network_name))

    ip = _split_adresses(net_prop['static_range'])
    gateway_name = net_prop['edge_gateway']
    if not vca_client.get_gateway(org_name, gateway_name):
        raise cfy_exc.NonRecoverableError(
            "Gateway {0} not found".format(gateway_name))
    start_address = check_ip(ip.start)
    end_address = check_ip(ip.end)
    gateway_ip = check_ip(net_prop["gateway_ip"])
    netmask = check_ip(net_prop["netmask"])
    dns1 = check_ip(net_prop["dns"]) if net_prop.get('dns') else ""
    dns2 = ""
    dns_suffix = net_prop.get("dns_suffix")
    success, result = vca_client.create_vdc_network(
        org_name, network_name, gateway_name, start_address,
        end_address, gateway_ip, netmask, dns1, dns2, dns_suffix)
    if success:
        ctx.logger.info("Network {0} has been successfully created."
                        .format(network_name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Could not create network {0}: {1}".format(network_name, result))
    wait_for_task(vca_client, result)
    ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = network_name
    _dhcp_operation(vca_client, network_name, ADD_POOL)


@operation
@with_vca_client
def delete(vca_client, **kwargs):
    if ctx.node.properties['use_external_resource'] is True:
        del ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        ctx.logger.info("Network was not deleted - external resource has"
                        " been used")
        return
    network_name = get_network_name(ctx.node.properties)
    _dhcp_operation(vca_client, network_name, DELETE_POOL)
    success, task = vca_client.delete_vdc_network(
        get_vcloud_config()['org'], network_name)
    if success:
        ctx.logger.info(
            "Network {0} has been successful deleted.".format(network_name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Could not delete network {0}".format(network_name))
    wait_for_task(vca_client, task)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
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
    if not vca_client.get_gateway(get_vcloud_config()['org'], gateway_name):
        raise cfy_exc.NonRecoverableError(
            "Gateway {0} not found".format(gateway_name))

    static_ip = _split_adresses(get_mandatory(net_prop, 'static_range'))
    check_ip(static_ip.start)
    check_ip(static_ip.end)
    check_ip(get_mandatory(net_prop, "dns"))
    gateway_ip = check_ip(get_mandatory(net_prop, "gateway_ip"))
    netmask = check_ip(get_mandatory(net_prop, "netmask"))

    ips = [gateway_ip, static_ip.start, static_ip.end]
    dhcp = net_prop.get("dhcp")
    if dhcp:
        dhcp_range = get_mandatory(net_prop["dhcp"], "dhcp_range")
        if not dhcp_range:
            raise cfy_exc.NonRecoverableError(
                "Parameter 'dhcp_range' not defined")
        dhcp_ip = _split_adresses(dhcp_range)
        if not is_separate_ranges(static_ip, dhcp_ip):
            raise cfy_exc.NonRecoverableError(
                "Static_range and dhcp_range is overlapped.")
        ips.extend([dhcp_ip.start, dhcp_ip.end])
    if not is_ips_in_same_subnet(ips, netmask):
            raise cfy_exc.NonRecoverableError(
                "IP addresses in divverent subnets.")


def _dhcp_operation(vca_client, network_name, operation):
    dhcp_settings = ctx.node.properties['network'].get('dhcp')
    if dhcp_settings is None:
        return
    gateway_name = ctx.node.properties["network"]['edge_gateway']
    gateway = vca_client.get_gateway(get_vcloud_config()['org'], gateway_name)
    if not gateway:
        raise cfy_exc.NonRecoverableError(
            "Gateway {0} not found!".format(gateway_name))

    if operation == ADD_POOL:
        ip = _split_adresses(dhcp_settings['dhcp_range'])
        low_ip_address = check_ip(ip.start)
        hight_ip_address = check_ip(ip.end)
        default_lease = dhcp_settings.get('default_lease')
        max_lease = dhcp_settings.get('max_lease')
        gateway.add_dhcp_pool(network_name, low_ip_address, hight_ip_address,
                              default_lease, max_lease)
        ctx.logger.info("DHCP rule successful created for network {0}"
                        .format(network_name))

    if operation == DELETE_POOL:
        gateway.delete_dhcp_pool(network_name)
        ctx.logger.info("DHCP rule successful deleted for network {0}"
                        .format(network_name))

    if not save_gateway_configuration(gateway, vca_client):
        return ctx.operation.retry(message='Waiting for gateway.',
                                   retry_after=10)


def _split_adresses(address_range):
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
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addresses: {0}".format(address_range))


def _get_network_list(vca_client, org_name):
    vdc = vca_client.get_vdc(org_name)
    if not vdc:
        raise cfy_exc.NonRecoverableError(
            "Vdc {0} not found.".format(org_name))
    return [net.name for net in vdc.AvailableNetworks.Network]
