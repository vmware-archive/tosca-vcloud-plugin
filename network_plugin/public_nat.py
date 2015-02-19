from cloudify import ctx
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config
from network_plugin import check_ip, save_gateway_configuration

VCLOUD_NETWORK_NAME = 'vcloud_network_name'
PUBLIC_IP = 'public_ip'
CREATE = 1
DELETE = 2


@operation
@with_vca_client
def connect_nat_to_network(vca_client, **kwargs):
    nat_network_operation(vca_client, CREATE)


@operation
@with_vca_client
def disconnect_nat_from_network(vca_client, **kwargs):
    nat_network_operation(vca_client, DELETE)


def nat_network_operation(vca_client, operation):
    network_name = ctx.target.node.properties['resource_id']
    vdc_name = get_vcloud_config()['vdc']
    public_ip = check_ip(ctx.source.node.properties['nat']['public_ip'])
    rule_type = ctx.source.node.properties['rules']['type']
    gateway = vca_client.get_gateway(vdc_name,
                                     ctx.source.node.properties['nat']['edge_gateway'])
    ip_ranges = _get_network_ip_range(vca_client, vdc_name, network_name)
    ip_ranges.extend(_get_gateway_ip_range(gateway, network_name))
    any_type = 'any'
    function = None
    message = None
    if operation == CREATE:
        function = gateway.add_nat_rule
        message = "Create"
    else:
        function = gateway.del_nat_rule
        message = "Delete"

    for rule in rule_type:
        for ip in ip_ranges:
            ctx.logger.info("{3} NAT rule: original_ip '{0}',"
                            "translated_ip '{1}', rule type '{2}'"
                            .format(ip, public_ip, rule, message))
            if rule == "SNAT":
                function(
                    rule, ip, any_type, public_ip, any_type, any_type)
            if rule == "DNAT":
                function(
                    rule, public_ip, any_type, ip, any_type, any_type)
    save_gateway_configuration(gateway, vca_client, "Could not save edge gateway NAT configuration")


def _get_network_ip_range(vca_client, vdc_name, network_name):
    networks = vca_client.get_networks(vdc_name)
    scopes = []
    for scope in [net.Configuration.IpScopes.IpScope for net in networks if network_name == net.get_name()]:
        for ip in scope[0].IpRanges.IpRange:
            scopes.append("{0} - {1}".format(ip.get_StartAddress(), ip.get_EndAddress()))
    return scopes


def _get_gateway_ip_range(gateway, network_name):
    scopes = []
    for pool in gateway.get_dhcp_pools():
        if pool.Network.name == network_name:
            scopes.append("{0} - {1}".format(pool.get_LowIpAddress(), pool.get_HighIpAddress()))
    return scopes
