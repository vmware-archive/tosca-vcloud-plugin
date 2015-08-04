# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (with_vca_client, get_vcloud_config,
                                  get_mandatory, is_subscription, is_ondemand)
from network_plugin import (check_ip, save_gateway_configuration,
                            get_vm_ip, get_public_ip,
                            get_gateway, getFreeIP, CREATE, DELETE, PUBLIC_IP,
                            del_ondemand_public_ip, utils, set_retry)
from network_plugin.network import VCLOUD_NETWORK_NAME
from IPy import IP

PORT_REPLACEMENT = 'port_replacement'
DEFAULT_SSH_PORT = '22'


@operation
@with_vca_client
def net_connect_to_nat_preconfigure(vca_client, **kwargs):
    rules = ctx.target.node.properties['rules']
    if len(rules) != 1:
        raise cfy_exc.NonRecoverableError(
            "Rules list must contains only one element")
    if _is_dnat(rules[0]['type']):
            raise cfy_exc.NonRecoverableError(
                "In 'cloudify.vcloud.net_connected_to_public_nat' relationship"
                " you can use only 'SNAT' rule.")


@operation
@with_vca_client
def net_connect_to_nat(vca_client, **kwargs):
    """
        create nat rule for current node
    """
    if ctx.target.node.properties.get('use_external_resource', False):
        ctx.logger.info("Using existing Public NAT.")
        return
    if not prepare_network_operation(vca_client, CREATE):
        return set_retry(ctx)


@operation
@with_vca_client
def net_disconnect_from_nat(vca_client, **kwargs):
    """
        drop nat rule for current node
    """
    if ctx.target.node.properties.get('use_external_resource', False):
        ctx.logger.info("Using existing Public NAT.")
        return
    if not prepare_network_operation(vca_client, DELETE):
        return set_retry(ctx)


@operation
@with_vca_client
def server_connect_to_nat(vca_client, **kwargs):
    """
        create nat rules for server
    """
    if not prepare_server_operation(vca_client, CREATE):
        return set_retry(ctx)


@operation
@with_vca_client
def server_disconnect_from_nat(vca_client, **kwargs):
    """
        drop nat rules for server
    """
    if not prepare_server_operation(vca_client, DELETE):
        return set_retry(ctx)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """
        validate nat rules in node properties
    """
    nat = get_mandatory(ctx.node.properties, 'nat')
    gateway = get_gateway(vca_client, get_mandatory(nat, 'edge_gateway'))
    service_type = get_vcloud_config().get('service_type')
    public_ip = nat.get(PUBLIC_IP)
    if public_ip:
        check_ip(public_ip)
    else:
        if is_subscription(service_type):
            getFreeIP(gateway)
    for rule in get_mandatory(ctx.node.properties, 'rules'):
        if _is_dnat(rule['type']):
            utils.check_protocol(rule.get('protocol'))
            original_port = rule.get('original_port')
            if original_port and not isinstance(original_port, int):
                raise cfy_exc.NonRecoverableError(
                    "Parameter 'original_port' must be integer")
            translated_port = rule.get('translated_port')
            if translated_port and not isinstance(translated_port, int):
                raise cfy_exc.NonRecoverableError(
                    "Parameter 'translated_port' must be integer")


def prepare_network_operation(vca_client, operation):
    """
        create nat rules by rules from network node
    """
    try:
        gateway = get_gateway(
            vca_client, ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _obtain_public_ip(vca_client, ctx, gateway, operation)
        private_ip = _create_ip_range(vca_client, gateway)
        for rule in ctx.target.node.properties['rules']:
            rule_type = rule['type']
            nat_network_operation(
                vca_client, gateway, operation,
                rule_type, public_ip,
                private_ip, "any", "any", "any")
    except KeyError as e:
        raise cfy_exc.NonRecoverableError(
            "Parameter not found: {0}".format(e)
        )
    return _save_configuration(gateway, vca_client, operation, public_ip)


def prepare_server_operation(vca_client, operation):
    """
        generate nat rules by current list of rules in node
    """
    try:
        gateway = get_gateway(
            vca_client, ctx.target.node.properties['nat']['edge_gateway'])
        public_ip = _obtain_public_ip(vca_client, ctx, gateway, operation)
        private_ip = get_vm_ip(vca_client, ctx, gateway)
        has_snat = False
        for rule in ctx.target.node.properties['rules']:
            rule_type = rule['type']
            if has_snat and _is_snat(rule_type):
                ctx.logger.info("Rules list must contains only one SNAT rule.")
                continue
            protocol = rule.get('protocol', "any")
            original_port = rule.get('original_port', "any")
            translated_port = rule.get('translated_port', "any")
            nat_network_operation(
                vca_client, gateway, operation,
                rule_type, public_ip,
                private_ip, original_port, translated_port, protocol)
            if _is_snat(rule_type):
                has_snat = True
    except KeyError as e:
        raise cfy_exc.NonRecoverableError("Parameter not found: {0}".format(e))
    return _save_configuration(gateway, vca_client, operation, public_ip)


def nat_network_operation(vca_client, gateway, operation, rule_type, public_ip,
                          private_ip, original_port, translated_port,
                          protocol):
    """
        create/drop nat rule for current network
    """
    if operation == CREATE:
        new_original_port = _get_original_port_for_create(
            gateway, rule_type, public_ip, original_port,
            private_ip, translated_port, protocol)
        function = gateway.add_nat_rule
        message = "Add"
        if _is_dnat(rule_type) and str(translated_port) == DEFAULT_SSH_PORT:
            ctx.source.instance.runtime_properties['ssh_port'] = str(new_original_port)
    elif operation == DELETE:
        new_original_port = _get_original_port_for_delete(
            public_ip, original_port)
        function = gateway.del_nat_rule
        message = "Remove"
    else:
        raise cfy_exc.NonRecoverableError(
            "Unknown operation: {0}".format(operation))

    info_message = ("{6} NAT rule: rule type '{2}', original_ip '{0}', "
                    "translated_ip '{1}',protocol '{3}', "
                    "original_port '{4}', translated_port '{5}'")
    if _is_snat(rule_type):
        # for SNAT type ports and protocol must by "any",
        #  because they are not configurable
        ctx.logger.info(
            info_message.format(private_ip, public_ip, rule_type, protocol,
                                new_original_port, translated_port,
                                message))
        function(
            rule_type, private_ip, "any", public_ip, "any", "any")
    elif _is_dnat(rule_type):
        ctx.logger.info(
            info_message.format(public_ip, private_ip, rule_type, protocol,
                                new_original_port, translated_port,
                                message))
        function(rule_type, public_ip, str(new_original_port), private_ip,
                 str(translated_port), protocol)
    else:
        raise cfy_exc.NonRecoverableError(
            "Unknown rule type: {0}".format(rule_type))


def _save_configuration(gateway, vca_client, operation, public_ip):
    """
        save/refresh nat rules on gateway
    """
    success = save_gateway_configuration(gateway, vca_client)
    if not success:
        return False
    ctx.logger.info("NAT configuration has been saved")
    if operation == CREATE:
        ctx.target.instance.runtime_properties[PUBLIC_IP] = public_ip
    else:
        service_type = get_vcloud_config().get('service_type')
        if is_ondemand(service_type):
            if not ctx.target.node.properties['nat'].get(PUBLIC_IP):
                del_ondemand_public_ip(
                    vca_client, gateway,
                    ctx.target.instance.runtime_properties[PUBLIC_IP],
                    ctx
                )
        if PUBLIC_IP in ctx.target.instance.runtime_properties:
            del ctx.target.instance.runtime_properties[PUBLIC_IP]
        if PORT_REPLACEMENT in ctx.target.instance.runtime_properties:
            del ctx.target.instance.runtime_properties[PORT_REPLACEMENT]
    return True


def _create_ip_range(vca_client, gateway):
    """
        return ip range by avaible ranges from gateway and current network
    """
    network_name = ctx.source.instance.runtime_properties[VCLOUD_NETWORK_NAME]
    org_name = get_vcloud_config()['org']
    net = _get_network_ip_range(vca_client, org_name, network_name)
    gate = _get_gateway_ip_range(gateway, network_name)
    if not net:
        raise cfy_exc.NonRecoverableError(
            "Unknown network: {0}".format(network_name))
    if gate:
        return "{} - {}".format(min(net[0], gate[0]), max(net[1], gate[1]))
    else:
        return "{} - {}".format(min(net), max(net))


def _get_network_ip_range(vca_client, org_name, network_name):
    """
        return ips for network from network configuration ipscopes
    """
    networks = vca_client.get_networks(org_name)
    ip_scope = [net.Configuration.IpScopes.IpScope
                for net in networks if network_name == net.get_name()]
    addresses = []
    for scope in ip_scope:
        for ip in scope[0].IpRanges.IpRange:
            addresses.append(IP(ip.get_StartAddress()))
            addresses.append(IP(ip.get_EndAddress()))
    if addresses:
        return min(addresses), max(addresses)
    else:
        return None


def _get_gateway_ip_range(gateway, network_name):
    """
        return avaible ip ranges for current gateway
    """
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


def _obtain_public_ip(vca_client, ctx, gateway, operation):
    """
        return public ip for rules,
        in delete case - returned already used
        in create case - return new free ip
    """
    public_ip = None
    if operation == CREATE:
        public_ip = ctx.target.node.properties['nat'].get(PUBLIC_IP)
        if not public_ip:
            service_type = get_vcloud_config().get('service_type')
            public_ip = get_public_ip(vca_client, gateway, service_type, ctx)
    elif operation == DELETE:
        if PUBLIC_IP in ctx.target.instance.runtime_properties:
            public_ip = ctx.target.instance.runtime_properties[PUBLIC_IP]
        else:
            raise cfy_exc.NonRecoverableError(
                "Can't obtain public IP from runtime properties")
    else:
        raise cfy_exc.NonRecoverableError("Unknown operation")

    return public_ip


def _get_original_port_for_create(
    gateway, rule_type, original_ip, original_port, translated_ip,
    translated_port, protocol
):
    """
        return port that can be used in rule, if port have already used
        return new port that is next free port after current
    """
    ctx.target.instance.runtime_properties.setdefault(PORT_REPLACEMENT, {})
    nat_rules = gateway.get_nat_rules()
    if isinstance(
            original_port, basestring) and original_port.lower() == 'any':
        if _is_rule_exists(
                nat_rules, rule_type, original_ip,
                original_port, translated_ip,
                translated_port, protocol):
            raise cfy_exc.NonRecoverableError(
                "The same NAT rule already exsists: "
                "original_ip '{0}',translated_ip '{1}', "
                "rule type '{2}', protocol '{3}', original_port '{4}, "
                "translated_port {5}'".format(
                    original_ip, translated_ip, rule_type, protocol,
                    original_port, translated_port))
        else:
            return original_port

    # origin port can be string
    for port in xrange(int(original_port), utils.MAX_PORT_NUMBER + 1):
        if not _is_rule_exists(nat_rules, rule_type, original_ip,
                               port, translated_ip,
                               translated_port, protocol):
            if port == original_port:
                return original_port
            else:
                ctx.logger.info(
                    "For IP {} replace original port {} -> {}"
                    .format(original_ip, original_port, port))
                key = '{}:{}'.format(original_ip, original_port)
                ctx.target.instance.runtime_properties[
                    PORT_REPLACEMENT][key] = port
                return port
    raise cfy_exc.NonRecoverableError(
        "Can't create NAT rule because maximum port number was reached")


def _get_original_port_for_delete(original_ip, original_port):
    """
        check may be we already replaced port by some new free port
    """
    runtime_properties = ctx.target.instance.runtime_properties
    if PORT_REPLACEMENT not in runtime_properties:
        return original_port
    key = '{}:{}'.format(original_ip, original_port)
    port = runtime_properties[PORT_REPLACEMENT].get(key)
    return port if port else original_port


def _is_rule_exists(nat_rules, rule_type,
                    original_ip, original_port,
                    translated_ip, translated_port, protocol):
    """
        check if we already have some rule with same properties
    """
    # gatewayNatRule properties may be None or string
    # convert to str, bacause port can be int
    cicmp = lambda t: t[1] and (str(t[0]).lower() == str(t[1]).lower())
    for natRule in nat_rules:
        gatewayNatRule = natRule.get_GatewayNatRule()
        if (all(map(cicmp, [
           (rule_type, natRule.get_RuleType()),
           (original_ip, gatewayNatRule.get_OriginalIp()),
           (str(original_port), gatewayNatRule.get_OriginalPort())]))):
            break
    else:
        return False
    return True


def _is_snat(value):
    return value.upper() == 'SNAT'


def _is_dnat(value):
    return value.upper() == 'DNAT'
