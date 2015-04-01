from IPy import IP
from cloudify import exceptions as cfy_exc
import collections
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType
from vcloud_plugin_common import (wait_for_task, get_vcloud_config,
                                  is_subscription)

VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
PUBLIC_IP = 'public_ip'
NAT_ROUTED = 'natRouted'
CREATE = 1
DELETE = 2


AssignedIPs = collections.namedtuple('AssignedIPs', 'external internal')
BUSY_MESSAGE = "The entity gateway is busy completing an operation."


def check_ip(address):
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
    return IP(start) < IP(end)


def is_separate_ranges(first, second):
    return IP(first.end) < IP(second.start) or IP(first.start) > IP(second.end)


def is_ips_in_same_subnet(ips, netmask):
    subnets = [IP("{0}/{1}".format(ip, netmask), make_net=True) for ip in ips]
    return len(set(subnets)) == 1


def CheckAssignedExternalIp(ip, gateway):
    if ip in [address.external for address in collectAssignedIps(gateway)]:
        raise cfy_exc.NonRecoverableError(
            "IP address: {0} already assigned. Gateway has free IP: {1}"
            .format(ip, getFreeIP(gateway)))


def CheckAssignedInternalIp(ip, gateway):
    if ip in [address.internal for address in collectAssignedIps(gateway)]:
        raise cfy_exc.NonRecoverableError(
            "VM private IP {0} already has public ip assigned ".format(ip))


def collectAssignedIps(gateway):
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
        raise cfy_exc.NonRecoverableError("Primary network {0} not connected"
                                          .format(connection['network_name']))
    except IndexError:
        raise cfy_exc.NonRecoverableError("Could not get vm IP address")


def get_vapp_name(runtime_properties):
    vapp_name = runtime_properties.get(VCLOUD_VAPP_NAME)
    if not vapp_name:
        raise cfy_exc.NonRecoverableError(
            "Could not find vApp name in runtime properties")
    return vapp_name


def save_gateway_configuration(gateway, vca_client):
    task = gateway.save_services_configuration()
    if task:
        wait_for_task(vca_client, task)
        return True
    else:
        error = taskType.parseString(gateway.response.content, True)
        if BUSY_MESSAGE in error.message:
            return False
        else:
            raise cfy_exc.NonRecoverableError(error.message)


def getFreeIP(gateway):
    public_ips = set(gateway.get_public_ips())
    allocated_ips = set([address.external
                         for address in collectAssignedIps(gateway)])
    available_ips = public_ips - allocated_ips
    if not available_ips:
        raise cfy_exc.NonRecoverableError(
            "Can't get external IP address")
    return list(available_ips)[0]


def get_network_name(properties):
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
    return bool(vca_client.get_network(get_vcloud_config()['vdc'],
                                       network_name))


def is_network_routed(vca_client, network_name, gateway):
    network = get_network(vca_client, network_name)
    if network.get_Configuration().get_FenceMode() != NAT_ROUTED:
        return False
    interfaces = gateway.get_interfaces('internal')
    for interface in interfaces:
        if interface.get_Name() == network_name:
            return True
    return False


def get_network(vca_client, network_name):
    if not network_name:
        raise cfy_exc.NonRecoverableError(
            "Network name is empty".format(network_name))
    network = vca_client.get_network(get_vcloud_config()['vdc'], network_name)
    if not network:
        raise cfy_exc.NonRecoverableError(
            "Network {0} could not be found".format(network_name))
    return network


def get_ondemand_public_ip(vca_client, gateway, ctx):
    old_public_ips = set(gateway.get_public_ips())
    task = gateway.allocate_public_ip()
    if task:
        wait_for_task(vca_client, task)
    else:
        raise cfy_exc.NonRecoverableError(
            "Can't get public ip for ondemand service")
    # update gateway for new IP address
    gateway = vca_client.get_gateways(get_vcloud_config()['vdc'])[0]
    new_public_ips = set(gateway.get_public_ips())
    new_ip = new_public_ips - old_public_ips
    if new_ip:
        ctx.logger.info("Assign public IP {0}".format(new_ip))
    else:
        raise cfy_exc.NonRecoverableError(
            "Can't get new public IP address")
    return list(new_ip)[0]


def del_ondemand_public_ip(vca_client, gateway, ip, ctx):
    task = gateway.deallocate_public_ip(ip)
    if task:
        wait_for_task(vca_client, task)
        ctx.logger.info("Public IP {0} deallocated".format(ip))
    else:
        raise cfy_exc.NonRecoverableError(
            "Can't deallocate public ip {0} for ondemand service".format(ip))


def get_public_ip(vca_client, gateway, service_type, ctx):
    if is_subscription(service_type):
        public_ip = getFreeIP(gateway)
        ctx.logger.info("Assign external IP {0}".format(public_ip))
    else:
        public_ip = get_ondemand_public_ip(vca_client, gateway, ctx)
    return public_ip


def get_gateway(vca_client, gateway_name):
    gateway = vca_client.get_gateway(get_vcloud_config()['vdc'],
                                     gateway_name)
    if not gateway:
        raise cfy_exc.NonRecoverableError(
            "Gateway {0}  not found".format(gateway_name))
    return gateway


def check_protocol(protocol):
    valid_protocols = ["Tcp", "Udp", "Icmp", "Any"]
    protocol = protocol.capitalize()
    if protocol not in valid_protocols:
        raise cfy_exc.NonRecoverableError(
            "Unknown protocol: {0}. Valid protocols are: {1}"
            .format(protocol, valid_protocols))
    return protocol


def check_port(port):
    if isinstance(port, int):
        if port > 0 and port < 65536:
            return port
        else:
            raise cfy_exc.NonRecoverableError(
                "Invalid 'port' value. Port value must be between 1 and 65535")
    elif isinstance(port, unicode):
            if port.lower() == "any":
                return port.lower()
    else:
        raise cfy_exc.NonRecoverableError(
            "Parameter 'port' must be integer, or 'any'")
