from IPy import IP
from cloudify import exceptions as cfy_exc
import collections

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
