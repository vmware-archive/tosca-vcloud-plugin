from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config, get_mandatory, isSubscription, isOndemand
from network_plugin import (check_ip, save_gateway_configuration,
                            get_vm_ip, CheckAssignedExternalIp, get_public_ip, get_gateway,
                            getFreeIP, CREATE, DELETE, PUBLIC_IP, check_protocol, del_ondemand_public_ip)
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
    nat = get_mandatory(ctx.node.properties, 'nat')
    rules = get_mandatory(ctx.node.properties, 'rules')
    gateway = get_gateway(vca_client, get_mandatory(nat, 'edge_gateway'))
    service_type = get_vcloud_config().get('service_type')
    public_ip = nat.get(PUBLIC_IP)
    if public_ip:
        check_ip(public_ip)
        CheckAssignedExternalIp(public_ip, gateway)
    else:
        if isSubscription(service_type):
            getFreeIP(gateway)
    check_protocol(rules.get('protocol', "any"))
    original_port = rules.get('original_port')
    if original_port and not isinstance(original_port, int):
        raise cfy_exc.NonRecoverableError("Parameter 'original_port' must be integer")
    translated_port = rules.get('translated_port')
    if translated_port and not isinstance(translated_port, int):
        raise cfy_exc.NonRecoverableError("Parameter 'translated_port' must be integer")


def prepare_network_operation(vca_client, operation):
    try:
        network_name = ctx.source.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        org_name = get_vcloud_config()['org']
        rule_type = ctx.target.node.properties['rules']['type']
        gateway = get_gateway(vca_client,
                              ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _get_public_ip(vca_client, ctx, gateway, operation)
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    ip_ranges = _get_network_ip_range(vca_client, org_name, network_name)
    ip_ranges.extend(_get_gateway_ip_range(gateway, network_name))
    nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, ip_ranges, "any", "any", "any")


def prepare_vm_operation(vca_client, operation):
    try:
        rule_type = ctx.target.node.properties['rules']['type']
        gateway = get_gateway(vca_client,
                              ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _get_public_ip(vca_client, ctx, gateway, operation)
        rule_type = ctx.target.node.properties['rules']['type']
        protocol = ctx.target.node.properties['rules'].get('protocol', "any")
        original_port = ctx.target.node.properties['rules'].get('original_port', "any")
        translated_port = ctx.target.node.properties['rules'].get('translated_port', "any")
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    private_ip = get_vm_ip(vca_client, ctx)
    nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, [private_ip], original_port, translated_port, protocol)


def nat_network_operation(vca_client, gateway, operation, rule_type, public_ip, private_ip, original_port, translated_port, protocol):
    ctx.logger.info("Public Ip {0}".format(public_ip))
    function = None
    message = None
    if operation == CREATE:
        CheckAssignedExternalIp(public_ip, gateway)
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

    if not  save_gateway_configuration(gateway, vca_client):
        return ctx.operation.retry(message='Waiting for gateway.',
                                   retry_after=10)

    if operation == CREATE:
        ctx.target.instance.runtime_properties[PUBLIC_IP] = public_ip
    else:
        service_type = get_vcloud_config().get('service_type')
        if isOndemand(service_type):
            if not ctx.target.node.properties['nat'].get(PUBLIC_IP):
                del_ondemand_public_ip(vca_client, gateway, ctx.target.instance.runtime_properties[PUBLIC_IP], ctx)
        del ctx.target.instance.runtime_properties[PUBLIC_IP]


def _get_network_ip_range(vca_client, org_name, network_name):
    networks = vca_client.get_networks(org_name)
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


def _get_public_ip(vca_client, ctx, gateway, operation):
    public_ip = None
    if operation == CREATE:
        public_ip = ctx.target.node.properties['nat'].get(PUBLIC_IP)
        if public_ip:
            CheckAssignedExternalIp(public_ip, gateway)
        else:
            service_type = get_vcloud_config().get('service_type')
            public_ip = get_public_ip(vca_client, gateway, service_type, ctx)
    elif operation == DELETE:
        if PUBLIC_IP in ctx.target.instance.runtime_properties:
            public_ip = ctx.target.instance.runtime_properties[PUBLIC_IP]
    if not public_ip:
        raise cfy_exc.NonRecoverableError("Can't get public IP")
    return public_ip
