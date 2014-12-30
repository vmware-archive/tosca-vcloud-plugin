from IPy import IP
from cloudify import exceptions as cfy_exc


def check_ip(address):
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addres: {0}".format(address))
    return address

def collectExternalIps(gateway):
    ips = []
    if gateway:
        for natRule in gateway.get_nat_rules():
            rule = natRule.get_GatewayNatRule()
            rule_type = natRule.get_RuleType()
            if rule_type == "DNAT":
                ips.append(rule.get_OriginalIp())
            else:
                ips.append(rule.get_TranslatedIp())
    return set(ips)
