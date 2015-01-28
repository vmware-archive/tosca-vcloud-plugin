from IPy import IP
from cloudify import exceptions as cfy_exc
import collections
from server_plugin import VAppOperations
from server_plugin.server import VCLOUD_VAPP_NAME

AssignedIPs = collections.namedtuple('AssignedIPs', 'external internal')


def check_ip(address):
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip address: {0}".format(address))
    return address


def isExternalIpAssigned(ip, gateway):
    return ip in [address.external for address in collectAssignedIps(gateway)]


def isInternalIpAssigned(ip, gateway):
    return ip in [address.internal for address in collectAssignedIps(gateway)]


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


def get_vm_ip(vcd_client, ctx):
    try:
        vappName = _get_vapp_name(ctx.source.instance.runtime_properties)
        vapp = vcd_client.get_vApp(vappName)
        if not vapp:
            raise cfy_exc.NonRecoverableError("Could not find vApp {0}".format(vappName))
        vapp_ops = VAppOperations(vcd_client, vapp)
        vm_info = vapp_ops.get_vms_network_info()
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
