from IPy import IP
from cloudify import exceptions as cfy_exc
import collections

from vcloud_plugin_common import wait_for_task, get_vcloud_config, isSubscription

VCLOUD_VAPP_NAME = 'vcloud_vapp_name'
PUBLIC_IP = 'public_ip'
CREATE = 1
DELETE = 2


AssignedIPs = collections.namedtuple('AssignedIPs', 'external internal')


def check_ip(address):
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect IP address: {0}".format(address))
    except TypeError as e:
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
            "IP address: {0} already assigned. Gateway has free IP: {1}".format(ip, getFreeIP(gateway)))


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
                ips.append(AssignedIPs(rule.get_OriginalIp(), rule.get_TranslatedIp()))
            else:
                ips.append(AssignedIPs(rule.get_TranslatedIp(), rule.get_OriginalIp()))
    return set(ips)


def get_vm_ip(vca_client, ctx):
    try:
        vappName = _get_vapp_name(ctx.source.instance.runtime_properties)
        vdc = vca_client.get_vdc(get_vcloud_config()['vdc'])
        vapp = vca_client.get_vapp(vdc, vappName)
        if not vapp:
            raise cfy_exc.NonRecoverableError("Could not find vApp {0}".format(vappName))

        vm_info = vapp.get_vms_network_info()
        # assume that we have 1 vm per vApp with minium 1 connection
        connection = vm_info[0][0]
        if connection['is_connected']:
            return connection['ip']
        else:
            raise cfy_exc.NonRecoverableError("Network not connected")
    except IndexError:
        raise cfy_exc.NonRecoverableError("Could not get vm IP address")


def _get_vapp_name(runtime_properties):
    try:
        return runtime_properties[VCLOUD_VAPP_NAME]
    except (IndexError, AttributeError):
        raise cfy_exc.NonRecoverableError("Could not find vApp by name")


def save_gateway_configuration(gateway, vca_client, message):
    task = gateway.save_services_configuration()
    if not task:
        raise cfy_exc.NonRecoverableError(
            message)
    wait_for_task(vca_client, task)


def getFreeIP(gateway):
    public_ips = set(gateway.get_public_ips())
    allocated_ips = set([address.external for address in collectAssignedIps(gateway)])
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
    networks = vca_client.get_networks(get_vcloud_config()['vdc'])
    return any([network_name == net.get_name() for net in networks])


def get_network(vca_client, network_name):
    if not network_name:
        raise cfy_exc.NonRecoverableError(
            "Network name is empty".format(network_name))
    result = None
    networks = vca_client.get_networks(get_vcloud_config()['vdc'])
    for network in networks:
        if network.get_name() == network_name:
            result = network
    if result is None:
        raise cfy_exc.NonRecoverableError(
            "Network {0} could not be found".format(network_name))
    return result


def get_ondemand_public_ip(vca_client, gateway, ctx):
    old_public_ips = set(gateway.get_public_ips())
    task = gateway.allocate_public_ip()
    if task:
        wait_for_task(vca_client, task)
    else:
        raise cfy_exc.NonRecoverableError("Can't get public ip for ondemand service")
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
        raise cfy_exc.NonRecoverableError("Can't deallocate public ip {0} for ondemand service".format(ip))


def get_public_ip(vca_client, gateway, service_type, ctx):
    if isSubscription(service_type):
        public_ip = getFreeIP(gateway)
        ctx.logger.info("Assign external IP {0}".format(public_ip))
    else:
        public_ip = get_ondemand_public_ip(vca_client, gateway, ctx)
    return public_ip


def get_gateway(vca_client, gateway_name):
    gateway = vca_client.get_gateway(get_vcloud_config()['vdc'],
                                     gateway_name)
    if not gateway:
        raise cfy_exc.NonRecoverableError("Gateway {0}  not found".format(gateway_name))
    return gateway


def check_protocol(protocol):
    valid_protocols = ["Tcp", "Udp", "Icmp", "Any"]
    protocol = protocol.capitalize()
    if protocol not in valid_protocols:
        raise cfy_exc.NonRecoverableError(
            "Unknown protocol: {0}. Valid protocols are: {1}".format(protocol, valid_protocols))
    return protocol

def check_port(port):
    if isinstance(port, int):
        if port > 0 and port < 65536:
            return port
        else:
            raise cfy_exc.NonRecoverableError("Invalid 'port' value. Port value must be between 1 and 65535")
    elif isinstance(port, unicode):
            if port.lower() == "any":
                return port.lower()
    else:
        raise cfy_exc.NonRecoverableError("Parameter 'port' must be integer, or 'any'")
