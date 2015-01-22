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
import collections
from network_plugin import check_ip
from network_operations import ProxyVCD

VCLOUD_NETWORK_NAME = 'vcloud_network_name'
ADD_POOL = 1
DELETE_POOL = 2


@operation
@with_vcd_client
def create(vcd_client, **kwargs):
    vcd_client = ProxyVCD(vcd_client) # TODO: remove when our code merged in pyvcloud
    if ctx.node.properties['use_external_resource'] is True:
        # TODO add check valid resource_id
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = \
            ctx.node.properties['resource_id']
        ctx.logger.info("External resource has been used")
        return
    net_prop = ctx.node.properties["network"]
    network_name = net_prop["name"]\
        if "name" in net_prop\
           else ctx.node.properties['resource_id']
    if network_name in _get_network_list(vcd_client):
        ctx.logger.info("Network {0} already exists".format(network_name))
        return
    ip = _split_adresses(net_prop['static_range'])
    gateway_name = net_prop['gateway_name']
    start_address = check_ip(ip.start)
    end_address = check_ip(ip.end)
    gateway_ip = check_ip(net_prop["gateway_ip"])
    netmask = check_ip(net_prop["netmask"])
    dns1 = check_ip(net_prop["dns"])
    dns2 = ""
    dns_suffix = net_prop["dns_duffix"]
    success, result = vcd_client.create_vdc_network(network_name, gateway_name, start_address,
                                                    end_address, gateway_ip, netmask,
                                                    dns1, dns2, dns_suffix)
    if success:
        ctx.logger.info("Network {0} has been successful created.".format(network_name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Could not create network{0}: {1}".format(network_name, result))
    wait_for_task(vcd_client, result)
    _dhcp_operation(vcd_client, network_name, ADD_POOL)


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    vcd_client = ProxyVCD(vcd_client) # TODO: remove when our code merged in pyvcloud
    if ctx.node.properties['use_external_resource'] is True:
        del ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        ctx.logger.info("Network was not deleted - external resource has"
                        " been used")
        return
    network_name = ctx.node.properties["network"]["name"]\
        if "name" in ctx.node.properties["network"]\
           else ctx.node.properties['resource_id']
    _dhcp_operation(vcd_client, network_name, DELETE_POOL)
    success, task = vcd_client.delete_vdc_network(network_name)
    if success:
        ctx.logger.info("Network {0} has been successful deleted.".format(network_name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Could not delete network {0}".format(network_name))
    wait_for_task(vcd_client, task)


def _dhcp_operation(vcd_client, network_name, operation):
    if 'dhcp' not in ctx.node.properties or not ctx.node.properties['dhcp']:
        return
    gateway_name = ctx.node.properties["network"]['gateway_name']
    gateway = vcd_client.get_gateway(gateway_name)
    if not gateway:
                raise cfy_exc.NonRecoverableError("Gateway {0} not found!".format(gateway_name))
    dhcp_settings = ctx.node.properties['dhcp']
    task = None
    if operation == ADD_POOL:
        ip = _split_adresses(dhcp_settings['dhcp_range'])
        low_ip_address = check_ip(ip.start)
        hight_ip_address = check_ip(ip.end)
        default_lease = dhcp_settings['default_lease'] if 'default_lease' in dhcp_settings else None
        max_lease = dhcp_settings['max_lease'] if 'max_lease' in dhcp_settings else None
        success, task = gateway.add_dhcp_pool(network_name, low_ip_address, hight_ip_address,
                                              default_lease, max_lease)
        if success:
            ctx.logger.info("DHCP rule successful created for network {0}".format(network_name))
        else:
            raise cfy_exc.NonRecoverableError("Could not add DHCP pool")

    if operation == DELETE_POOL:
        success, task = gateway.delete_dhcp_pool(network_name)
        if success:
            ctx.logger.info("DHCP rule successful deleted for network {0}".format(network_name))
        else:
            raise cfy_exc.NonRecoverableError("Could not delete DHCP pool")
    if task:
        wait_for_task(vcd_client, task)


def _split_adresses(address_range):
    adresses = [ip.strip() for ip in address_range.split('-')]
    IPRange = collections.namedtuple('IPRange', 'start end')
    try:
        start = check_ip(adresses[0])
        end = check_ip(adresses[1])
        if start > end:
            raise cfy_exc.NonRecoverableError(
                "Start address {0} is greater than end address: {1}".format(start, end))
        return IPRange(start=start,  end=end)
    except IndexError:
        raise cfy_exc.NonRecoverableError("Can't parse IP range:{0}".
                                          format(address_range))
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addresses: {0}".format(address_range))


def _get_network_list(vcd_client):
    vdc = vcd_client._get_vdc()
    return [net.name for net in vdc.AvailableNetworks.Network]
