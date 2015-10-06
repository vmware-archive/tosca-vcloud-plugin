# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
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

from IPy import IP
from cloudify import exceptions as cfy_exc
import collections
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType
from vcloud_plugin_common import (wait_for_task, get_vcloud_config,
                                  is_subscription, error_response)
from cloudify_rest_client import exceptions as rest_exceptions
import time
from functools import wraps
from cloudify.manager import get_rest_client

VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
PUBLIC_IP = 'public_ip'
SSH_PUBLIC_IP = 'ssh_public_ip'
SSH_PORT = 'ssh_port'
NAT_ROUTED = 'natRouted'
GATEWAY_LOCK = 'gateway_lock'
CREATE = 1
DELETE = 2


AssignedIPs = collections.namedtuple('AssignedIPs', 'external internal')
BUSY_MESSAGE = "is busy completing an operation"

GATEWAY_TIMEOUT = 30
# try n times before fail
RETRY_COUNT = 10
# sleep n seconds before retry
RETRY_SLEEP = 10


def check_ip(address):
    """
        check ip format
    """
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect IP address: {0}".format(address))
    except TypeError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect type of IP address value : {0}".format(address))
    return address


def is_valid_ip_range(start, end):
    """
        check start ip < end ip
    """
    return IP(start) < IP(end)


def is_separate_ranges(first, second):
    """
        check that we dont have shared ips in ranges, e.g
        first.end < second.start or first.start > second.end
    """
    return IP(first.end) < IP(second.start) or IP(first.start) > IP(second.end)


def is_ips_in_same_subnet(ips, netmask):
    """
        check that we have ip with same mask
    """
    subnets = [IP("{0}/{1}".format(ip, netmask), make_net=True) for ip in ips]
    return len(set(subnets)) == 1


def CheckAssignedExternalIp(ip, gateway):
    """
        check ip have already assigned to some node as public ip
    """
    if ip in [address.external for address in collectAssignedIps(gateway)]:
        raise cfy_exc.NonRecoverableError(
            "IP address: {0} already assigned. Gateway has free IP: {1}"
            .format(ip, getFreeIP(gateway)))


def CheckAssignedInternalIp(ip, gateway):
    """
        check ip have already assigned to som node as internal ip
    """
    if ip in [address.internal for address in collectAssignedIps(gateway)]:
        raise cfy_exc.NonRecoverableError(
            "VM private IP {0} already has public ip assigned ".format(ip))


def collectAssignedIps(gateway):
    """
        get full list of assigned ips as set of (external, internal)
    """
    ips = []
    if gateway:
        for natRule in gateway.get_nat_rules():
            rule = natRule.get_GatewayNatRule()
            rule_type = natRule.get_RuleType()
            if rule_type == "DNAT":
                ips.append(AssignedIPs(rule.get_OriginalIp(),
                                       rule.get_TranslatedIp()))
            else:
                ips.append(AssignedIPs(rule.get_TranslatedIp(),
                                       rule.get_OriginalIp()))
    return set(ips)


def get_vm_ip(vca_client, ctx, gateway):
    """
        get ip assigned to current vm from connected primary network.
    """
    try:
        vappName = get_vapp_name(ctx.source.instance.runtime_properties)
        vdc = vca_client.get_vdc(get_vcloud_config()['vdc'])
        vapp = vca_client.get_vapp(vdc, vappName)
        if not vapp:
            raise cfy_exc.NonRecoverableError(
                "Could not find vApp {0}".format(vappName))

        vm_info = vapp.get_vms_network_info()
        # assume that we have 1 vm per vApp
        for connection in vm_info[0]:
            if connection['is_connected'] and connection['is_primary']:
                if is_network_routed(vca_client,
                                     connection['network_name'],
                                     gateway):
                    return connection['ip']
                else:
                    raise cfy_exc.NonRecoverableError(
                        "Primary network {0} not routed"
                        .format(connection['network_name']))
        raise cfy_exc.NonRecoverableError("No connected primary network")
    except IndexError:
        raise cfy_exc.NonRecoverableError("Could not get vm IP address")


def get_vapp_name(runtime_properties):
    """
        get vapp name from runtime properties
    """
    vapp_name = runtime_properties.get(VCLOUD_VAPP_NAME)
    if not vapp_name:
        raise cfy_exc.NonRecoverableError(
            "Could not find vApp name in runtime properties")
    return vapp_name


def save_gateway_configuration(gateway, vca_client, ctx):
    """
        save gateway configuration,
        return everything successfully finished
        raise NonRecoverableError - can't get task description
    """
    task = gateway.save_services_configuration()
    if task:
        wait_for_task(vca_client, task)
        ctx.logger.info("Gateway parameters has been saved.")
        return True
    else:
        error = taskType.parseString(gateway.response.content, True)
        if BUSY_MESSAGE in error.message:
            ctx.logger.info("Gateway is busy.")
            return False
        else:
            raise cfy_exc.NonRecoverableError(error.message)


def getFreeIP(gateway):
    """
        return list of free public ips as difference
        between assigned ips to nodes and full list of public ip
        assigned to gateway
    """
    public_ips = set(gateway.get_public_ips())
    allocated_ips = set([address.external
                         for address in collectAssignedIps(gateway)])
    available_ips = public_ips - allocated_ips
    if not available_ips:
        raise cfy_exc.NonRecoverableError(
            "Can't get public IP address")
    return list(available_ips)[0]


def get_network_name(properties):
    """
        get network name from properties
    """
    if properties.get('use_external_resource'):
        name = properties.get('resource_id')
        if not name:
            raise cfy_exc.NonRecoverableError(
                "Parameter 'resource_id; for external resource not defined.")
        return name
    if not properties.get('network'):
        raise cfy_exc.NonRecoverableError(
            "Parameter 'network' for Network node not defined.")
    name = properties["network"].get("name")
    if not name:
        raise cfy_exc.NonRecoverableError(
            "Parameter 'name' for network properties not defined.")
    return name


def is_network_exists(vca_client, network_name):
    """
        network already exist
    """
    return bool(vca_client.get_network(get_vcloud_config()['vdc'],
                                       network_name))


def is_network_routed(vca_client, network_name, gateway):
    """
        network routed and exist in interfaces for this gateway
    """
    network = get_network(vca_client, network_name)
    if network.get_Configuration().get_FenceMode() != NAT_ROUTED:
        return False
    interfaces = gateway.get_interfaces('internal')
    for interface in interfaces:
        if interface.get_Name() == network_name:
            return True
    return False


def get_network(vca_client, network_name):
    """
        return network by name
    """
    if not network_name:
        raise cfy_exc.NonRecoverableError(
            "Network name is empty".format(network_name))
    network = vca_client.get_network(get_vcloud_config()['vdc'], network_name)
    if not network:
        raise cfy_exc.NonRecoverableError(
            "Network {0} could not be found".format(network_name))
    return network


def get_ondemand_public_ip(vca_client, gateway, ctx):
    """
        try to allocate new public ip for ondemand service
    """
    old_public_ips = set(gateway.get_public_ips())
    allocated_ips = set([address.external
                         for address in collectAssignedIps(gateway)])
    available_ips = old_public_ips - allocated_ips
    if available_ips:
        new_ip = list(available_ips)[0]
        ctx.logger.info("Public IP {0} was reused.".format(new_ip))
        return new_ip
    for i in xrange(RETRY_COUNT):
        ctx.logger.info("Try to allocate public IP")
        wait_for_gateway(vca_client, gateway.get_name(), ctx)
        task = gateway.allocate_public_ip()
        if task:
            try:
                wait_for_task(vca_client, task)
                break
            except cfy_exc.NonRecoverableError:
                continue
        else:
            raise cfy_exc.NonRecoverableError(
                "Can't get public ip for ondemand service {0}".
                format(error_response(gateway)))
    # update gateway for new IP address
    gateway = vca_client.get_gateways(get_vcloud_config()['vdc'])[0]
    new_public_ips = set(gateway.get_public_ips())
    new_ip = new_public_ips - old_public_ips
    if new_ip:
        ctx.logger.info("Public IP {0} was asigned.".format(new_ip))
    else:
        raise cfy_exc.NonRecoverableError(
            "Can't get new public IP address")
    return list(new_ip)[0]


def del_ondemand_public_ip(vca_client, gateway, ip, ctx):
    """
        try to deallocate public ip
    """
    ctx.logger.info("Try to deallocate public IP {0}".format(ip))
    wait_for_gateway(vca_client, gateway.get_name(), ctx)
    task = gateway.deallocate_public_ip(ip)
    if task:
        wait_for_task(vca_client, task)
        ctx.logger.info("Public IP {0} was deallocated".format(ip))
    else:
        raise cfy_exc.NonRecoverableError(
            "Can't deallocate public ip {0}. {1} for ondemand service".
            format(ip, error_response(gateway)))


def get_public_ip(vca_client, gateway, service_type, ctx):
    """
        return new public ip
    """
    if is_subscription(service_type):
        public_ip = getFreeIP(gateway)
        ctx.logger.info("Assign external IP {0}".format(public_ip))
    else:
        public_ip = get_ondemand_public_ip(vca_client, gateway, ctx)
    return public_ip


def get_gateway(vca_client, gateway_name):
    """
        return gateway by name
    """
    gateway = vca_client.get_gateway(get_vcloud_config()['vdc'],
                                     gateway_name)
    if not gateway:
        raise cfy_exc.NonRecoverableError(
            "Gateway {0}  not found".format(gateway_name))
    return gateway


def set_retry(ctx):
    """
        set retry on cloudify level
    """
    return ctx.operation.retry(
        message='Waiting for gateway.',
        retry_after=GATEWAY_TIMEOUT)


def save_ssh_parameters(ctx, port, ip):
    """save port and ip for ssh to context"""
    retries_update = 3
    update_pending = True
    while retries_update > 0 and update_pending:
        retries_update = retries_update - 1
        try:
            ctx.source.instance.runtime_properties[SSH_PORT] = port
            ctx.source.instance.runtime_properties[SSH_PUBLIC_IP] = ip
            ctx.source.instance.update()
            update_pending = False
        except rest_exceptions.CloudifyClientError as e:
            if 'conflict' in str(e):
                # cannot 'return' in contextmanager
                ctx.logger.info(
                    "Conflict in updating backend, retrying")
            else:
                raise e


def wait_for_gateway(vca_client, gateway_name, ctx):
    """try ten times to wait 10 seconds for gateway"""
    for i in xrange(RETRY_COUNT):
        gateway = get_gateway(vca_client, gateway_name)
        if not gateway.is_busy():
            return
        ctx.logger.info("Check {0}. Gateway is busy.".format(i))
        time.sleep(RETRY_SLEEP)
    raise cfy_exc.NonRecoverableError(
        "Can't wait gateway {0}".format(gateway_name))


def _is_gateway_locked(ctx):
    if ctx.deployment.id == 'local':
        storage = ctx.internal.handler.storage
        node_instances = storage.get_node_instances()
    else:
        rest = get_rest_client()
        node_instances = rest.node_instances.list(ctx.deployment.id)
    for instance in node_instances:
            rt_properties = instance['runtime_properties']
            if rt_properties.get(GATEWAY_LOCK):
                return True
    return False


def lock_gateway(f):
    """loc gateway before operation"""
    def update_parameters(ctx, value):
        ctx.source.instance.runtime_properties[GATEWAY_LOCK] = value
        ctx.source.instance.update()

    @wraps(f)
    def wrapper(*args, **kw):
        ctx = kw['ctx']
        #  Reset for getting last version of runtime_properties
        #ctx.source.instance._node_instance = None
        if _is_gateway_locked(ctx):
            ctx.logger.info("Gateway locked.")
            return set_retry(ctx)
        try:
            ctx.logger.info("Lock gateway.")
            update_parameters(ctx, True)
            vca_client = kw['vca_client']
            gateway_name = get_vcloud_config().get('edge_gateway')
            if gateway_name:
                wait_for_gateway(vca_client, gateway_name, ctx)
            else:
                # we need gateway_name from vcloud for use this functionality
                ctx.logger.info(
                    "'edge_gateway' in vcloud_config is empty." +
                    " Can't check state of gateway correctly."
                )
            result = f(*args, **kw)
        finally:
            ctx.logger.info("Unlock gateway.")
            ctx.source.instance._node_instance = None
            update_parameters(ctx, False)
        return result
    return wrapper
