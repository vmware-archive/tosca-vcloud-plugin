from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config
from network_plugin import check_ip, save_gateway_configuration, get_vm_ip, isExternalIpAssigned, getFreeIP, CREATE, DELETE, PUBLIC_IP
from network_plugin.network import VCLOUD_NETWORK_NAME


@operation
@with_vca_client
def net_connect_to_nat(vca_client, **kwargs):
    prepare_network_operation(vca_client, CREATE)


@operation
@with_vca_client
def net_disconnect_from_nat(vca_client, **kwargs):
    prepare_network_operation(vca_client, DELETE)


@operation
@with_vca_client
def server_connect_to_nat(vca_client, **kwargs):
    prepare_vm_operation(vca_client, CREATE)


@operation
@with_vca_client
def server_disconnect_from_nat(vca_client, **kwargs):
    prepare_vm_operation(vca_client, DELETE)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    pass


def prepare_network_operation(vca_client, operation):
    try:
        network_name = ctx.source.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        vdc_name = get_vcloud_config()['vdc']
        rule_type = ctx.target.node.properties['rules']['type']
        gateway = vca_client.get_gateway(vdc_name,
                                         ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _get_public_ip(ctx, gateway, operation)
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    ip_ranges = _get_network_ip_range(vca_client, vdc_name, network_name)
    ip_ranges.extend(_get_gateway_ip_range(gateway, network_name))
    nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, ip_ranges, "any", "any", "any")


def prepare_vm_operation(vca_client, operation):
    try:
        vdc_name = get_vcloud_config()['vdc']
        rule_type = ctx.target.node.properties['rules']['type']
        gateway = vca_client.get_gateway(vdc_name,
                                         ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _get_public_ip(ctx, gateway, operation)
        rule_type = ctx.target.node.properties['rules']['type']
        protocol = ctx.target.node.properties['rules'].get('protocol', "any")
        original_port = ctx.target.node.properties['rules'].get('original_port', "any")
        translated_port = ctx.target.node.properties['rules'].get('translated_port', "any")
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    private_ip = check_ip(get_vm_ip(vca_client, ctx))
    nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, [private_ip], original_port, translated_port, protocol)


def nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, private_ip, original_port, translated_port, protocol):
    ctx.logger.info("Public Ip {0}".format(public_ip))
    function = None
    message = None
    if operation == CREATE:
        if isExternalIpAssigned(public_ip, gateway):
            raise cfy_exc.NonRecoverableError("Public IP {0} is already allocated".format(public_ip))
        function = gateway.add_nat_rule
        message = "Create"
    elif operation == DELETE:
        function = gateway.del_nat_rule
        message = "Delete"
    else:
        raise cfy_exc.NonRecoverableError("Unknown operation: {0}".format(operation))

    for rule in rule_type:
        for ip in private_ip:
            ctx.logger.info("{6} NAT rule: original_ip '{0}',"
                            " translated_ip '{1}', rule type '{2},"
                            " protocol {3}, original_port {4}, translated_port {5}'"
                            .format(ip, public_ip, rule, protocol, original_port, translated_port, message))
            if rule == "SNAT":
                # for SNAT type ports and protocol must by "any", because they are not configurable
                function(
                    rule, ip, "any", public_ip, "any", "any")
            if rule == "DNAT":
                function(
                    rule, public_ip, str(original_port), ip, str(translated_port), protocol)
    save_gateway_configuration(gateway, vca_client, "Could not save edge gateway NAT configuration")
    if operation == CREATE:
        ctx.target.instance.runtime_properties[PUBLIC_IP] = public_ip
    else:
        del ctx.target.instance.runtime_properties[PUBLIC_IP]


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


def _get_public_ip(ctx, gateway, operation):
    public_ip = None
    if operation == CREATE:
        if PUBLIC_IP in ctx.target.node.properties['nat']:
            public_ip = check_ip(ctx.target.node.properties['nat'][PUBLIC_IP])
        else:
            public_ip = getFreeIP(gateway)
            ctx.logger.info("Assign external IP {0}".format(public_ip))
    elif operation == DELETE:
        if PUBLIC_IP in ctx.target.instance.runtime_properties:
            public_ip = ctx.target.instance.runtime_properties[PUBLIC_IP]
    if not public_ip:
        raise cfy_exc.NonRecoverableError("Can't get public IP")
    return public_ip
