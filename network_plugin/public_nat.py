from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (with_vca_client, get_vcloud_config,
                                  get_mandatory, is_subscription, is_ondemand)
from network_plugin import (check_ip, save_gateway_configuration,
                            get_vm_ip, CheckAssignedExternalIp, get_public_ip,
                            get_gateway, getFreeIP, CREATE, DELETE, PUBLIC_IP,
                            check_protocol, del_ondemand_public_ip)
from network_plugin.network import VCLOUD_NETWORK_NAME
from IPy import IP


@operation
@with_vca_client
def net_connect_to_nat(vca_client, **kwargs):
    if ctx.target.node.properties['use_external_resource']:
        ctx.logger.info("Using existing Public NAT.")
        return
    prepare_network_operation(vca_client, CREATE)


@operation
@with_vca_client
def net_disconnect_from_nat(vca_client, **kwargs):
    if ctx.target.node.properties['use_external_resource']:
        ctx.logger.info("Using existing Public NAT.")
        return
    prepare_network_operation(vca_client, DELETE)


@operation
@with_vca_client
def server_connect_to_nat(vca_client, **kwargs):
    prepare_server_operation(vca_client, CREATE)


@operation
@with_vca_client
def server_disconnect_from_nat(vca_client, **kwargs):
    prepare_server_operation(vca_client, DELETE)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    nat = get_mandatory(ctx.node.properties, 'nat')
    gateway = get_gateway(vca_client, get_mandatory(nat, 'edge_gateway'))
    service_type = get_vcloud_config().get('service_type')
    public_ip = nat.get(PUBLIC_IP)
    if public_ip:
        check_ip(public_ip)
        CheckAssignedExternalIp(public_ip, gateway)
    else:
        if is_subscription(service_type):
            getFreeIP(gateway)
    for rule in get_mandatory(ctx.node.properties, 'rules'):
        if rule['type'] == "DNAT":
            check_protocol(rule.get('protocol', "any"))
            original_port = rule.get('original_port')
            if original_port and not isinstance(original_port, int):
                raise cfy_exc.NonRecoverableError(
                    "Parameter 'original_port' must be integer")
            translated_port = rule.get('translated_port')
            if translated_port and not isinstance(translated_port, int):
                raise cfy_exc.NonRecoverableError(
                    "Parameter 'translated_port' must be integer")


def prepare_network_operation(vca_client, operation):
    try:
        gateway = get_gateway(vca_client, ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _get_public_ip(vca_client, ctx, gateway, operation)
        private_ip = _create_ip_range(vca_client, gateway)
        if operation == CREATE:
            CheckAssignedExternalIp(public_ip, gateway)
        for rule in ctx.target.node.properties['rules']:
            rule_type = rule['type']
            nat_network_operation(vca_client, gateway, operation, rule_type, public_ip,
                                  private_ip, "any", "any", "any")
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    _save_configuration(gateway, vca_client, operation, public_ip)


def prepare_server_operation(vca_client, operation):
    try:
        gateway = get_gateway(vca_client, ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _get_public_ip(vca_client, ctx, gateway, operation)
        private_ip = get_vm_ip(vca_client, ctx, gateway)
        if operation == CREATE:
            CheckAssignedExternalIp(public_ip, gateway)
        for rule in ctx.target.node.properties['rules']:
            rule_type = rule['type']
            protocol = rule.get('protocol', "any")
            original_port = rule.get('original_port', "any")
            translated_port = rule.get('translated_port', "any")
            nat_network_operation(vca_client, gateway, operation, rule_type, public_ip,
                                  private_ip, original_port, translated_port,
                                  protocol)
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    _save_configuration(gateway, vca_client, operation, public_ip)


def nat_network_operation(vca_client, gateway, operation, rule_type, public_ip,
                          private_ip, original_port, translated_port,
                          protocol):
    ctx.logger.info("Public IP {0}".format(public_ip))
    function = None
    message = None
    if operation == CREATE:
        function = gateway.add_nat_rule
        message = "Create"
    elif operation == DELETE:
        function = gateway.del_nat_rule
        message = "Delete"
    else:
        raise cfy_exc.NonRecoverableError(
            "Unknown operation: {0}".format(operation))

    ctx.logger.info(
        "{6} NAT rule: original_ip '{0}',translated_ip '{1}', "
        "rule type '{2}, protocol {3}, original_port {4}, "
        "translated_port {5}'".format(private_ip, public_ip, rule_type, protocol,
                                      original_port, translated_port,
                                      message))
    if rule_type == "SNAT":
        # for SNAT type ports and protocol must by "any", because they
        # are not configurable
        function(
            rule_type, private_ip, "any", public_ip, "any", "any")
    if rule_type == "DNAT":
        function(rule_type, public_ip, str(original_port), private_ip,
                 str(translated_port), protocol)


def _save_configuration(gateway, vca_client, operation, public_ip):
    if not save_gateway_configuration(gateway, vca_client):
        return ctx.operation.retry(message='Waiting for gateway.',
                                   retry_after=10)

    if operation == CREATE:
        ctx.target.instance.runtime_properties[PUBLIC_IP] = public_ip
    else:
        service_type = get_vcloud_config().get('service_type')
        if is_ondemand(service_type):
            if not ctx.target.node.properties['nat'].get(PUBLIC_IP):
                del_ondemand_public_ip(
                    vca_client, gateway,
                    ctx.target.instance.runtime_properties[PUBLIC_IP], ctx)
        del ctx.target.instance.runtime_properties[PUBLIC_IP]


def _create_ip_range(vca_client, gateway):
        network_name = ctx.source.instance.runtime_properties[VCLOUD_NETWORK_NAME]
        org_name = get_vcloud_config()['org']
        net = _get_network_ip_range(vca_client, org_name, network_name)
        gate = _get_gateway_ip_range(gateway, network_name)
        if gate:
            return "{} - {}".format(min(net[0], gate[0]), max(net[1], gate[1]))
        else:
            return "{} - {}".format(min(net), max(net))


def _get_network_ip_range(vca_client, org_name, network_name):
    networks = vca_client.get_networks(org_name)
    ip_scope = [net.Configuration.IpScopes.IpScope
                for net in networks if network_name == net.get_name()]
    addresses = []
    for scope in ip_scope:
        for ip in scope[0].IpRanges.IpRange:
            addresses.append(IP(ip.get_StartAddress()))
            addresses.append(IP(ip.get_EndAddress()))
    return min(addresses), max(addresses)


def _get_gateway_ip_range(gateway, network_name):
    addresses = []
    pools = gateway.get_dhcp_pools()
    if not pools:
        return None
    for pool in pools:
        if pool.Network.name == network_name:
            addresses.append(IP(pool.get_LowIpAddress()))
            addresses.append(IP(pool.get_HighIpAddress()))
    if addresses:
        return min(addresses), max(addresses)
    else:
        return None


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
