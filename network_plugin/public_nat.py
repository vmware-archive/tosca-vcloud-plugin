from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config
from network_plugin import check_ip, save_gateway_configuration, get_vm_ip

VCLOUD_NETWORK_NAME = 'vcloud_network_name'
PUBLIC_IP = 'public_ip'
CREATE = 1
DELETE = 2


@operation
@with_vca_client
def connect_nat_to_network(vca_client, **kwargs):
    prepare_network_operation(vca_client, CREATE)


@operation
@with_vca_client
def disconnect_nat_from_network(vca_client, **kwargs):
    prepare_network_operation(vca_client, DELETE)


@operation
@with_vca_client
def connect_nat_to_vm(vca_client, **kwargs):
    prepare_vm_operation(vca_client, CREATE)


@operation
@with_vca_client
def disconnect_nat_from_vm(vca_client, **kwargs):
    prepare_vm_operation(vca_client, DELETE)


def prepare_network_operation(vca_client, operation):
    try:
        network_name = ctx.source.node.properties['resource_id']
        vdc_name = get_vcloud_config()['vdc']
        public_ip = check_ip(ctx.target.node.properties['nat']['public_ip'])
        rule_type = ctx.target.node.properties['rules']['type']
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    gateway = vca_client.get_gateway(vdc_name,
                                     ctx.target.node.properties['nat']['edge_gateway'])
    ip_ranges = _get_network_ip_range(vca_client, vdc_name, network_name)
    ip_ranges.extend(_get_gateway_ip_range(gateway, network_name))
    nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, ip_ranges, "any", "any", "any")


def prepare_vm_operation(vca_client, operation):
    try:
        vdc_name = get_vcloud_config()['vdc']
        public_ip = check_ip(ctx.target.node.properties['nat']['public_ip'])
        rule_type = ctx.target.node.properties['rules']['type']
        gateway = vca_client.get_gateway(vdc_name,
                                         ctx.target.node.properties['nat']['edge_gateway'])
        rule_type = ctx.target.node.properties['rules']['type']
        protocol = ctx.target.node.properties['rules']['protocol'] if 'protocol' in ctx.target.node.properties['rules'] else "any"
        original_port = ctx.target.node.properties['rules']['original_port'] if 'original_port' in ctx.target.node.properties['rules'] else "any"
        translated_port = ctx.target.node.properties['rules']['translated_port'] if 'translated_port' in ctx.target.node.properties['rules'] else "any"
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    private_ip = check_ip(get_vm_ip(vca_client, ctx))
    nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, [private_ip], original_port, translated_port, protocol)


def nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, private_ip, original_port, translated_port, protocol):
    function = None
    message = None
    if operation == CREATE:
        function = gateway.add_nat_rule
        message = "Create"
    else:
        function = gateway.del_nat_rule
        message = "Delete"

    for rule in rule_type:
        for ip in private_ip:
            ctx.logger.info("{3} NAT rule: original_ip '{0}',"
                            "translated_ip '{1}', rule type '{2}'"
                            .format(ip, public_ip, rule, message))
            if rule == "SNAT":
                function(
                    rule, ip, translated_port, public_ip, original_port, protocol)
            if rule == "DNAT":
                function(
                    rule, public_ip, original_port, ip, translated_port, protocol)
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
