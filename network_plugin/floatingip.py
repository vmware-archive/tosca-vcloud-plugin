from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config, isSubscription, isOndemand, get_mandatory
from network_plugin import (check_ip, CheckAssignedExternalIp, CheckAssignedInternalIp,
                            get_vm_ip, save_gateway_configuration, getFreeIP,
                            CREATE, DELETE, PUBLIC_IP, get_gateway, get_public_ip,
                            del_ondemand_public_ip)


@operation
@with_vca_client
def connect_floatingip(vca_client, **kwargs):
    _floatingip_operation(CREATE, vca_client, ctx)


@operation
@with_vca_client
def disconnect_floatingip(vca_client, **kwargs):
    _floatingip_operation(DELETE, vca_client, ctx)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    floatingip = get_mandatory(ctx.node.properties, 'floatingip')
    edge_gateway = get_mandatory(floatingip, 'edge_gateway')
    gateway = get_gateway(vca_client, edge_gateway)
    service_type = get_vcloud_config().get('service_type')
    public_ip = floatingip.get(PUBLIC_IP)
    if public_ip:
        check_ip(public_ip)
        CheckAssignedExternalIp(public_ip, gateway)
    else:
        if isSubscription(service_type):
            getFreeIP(gateway)


def _floatingip_operation(operation, vca_client, ctx):
    service_type = get_vcloud_config().get('service_type')
    gateway = get_gateway(vca_client,
                          ctx.target.node.properties['floatingip']['edge_gateway'])
    internal_ip = check_ip(get_vm_ip(vca_client, ctx))

    nat_operation = None
    public_ip = ctx.target.instance.runtime_properties.get(PUBLIC_IP) or \
                ctx.target.node.properties['floatingip'].get(PUBLIC_IP)
    if operation == CREATE:
        CheckAssignedInternalIp(internal_ip, gateway)
        if public_ip:
            CheckAssignedExternalIp(public_ip, gateway)
        else:
            public_ip = get_public_ip(vca_client, gateway, service_type, ctx)

        nat_operation = _add_nat_rule
    elif operation == DELETE:
        if not public_ip:
            ctx.logger.info("Can't get external IP".format(public_ip))
            return
        nat_operation = _del_nat_rule
    else:
        raise cfy_exc.NonRecoverableError(
            "Unknown operation {0}").format(operation)

    external_ip = check_ip(public_ip)

    nat_operation(gateway, vca_client, "SNAT", internal_ip, external_ip)
    nat_operation(gateway, vca_client, "DNAT", external_ip, internal_ip)
    save_gateway_configuration(gateway, vca_client, "Could not save edge gateway NAT configuration")

    if operation == CREATE:
        ctx.target.instance.runtime_properties[PUBLIC_IP] = external_ip
    else:
        if isOndemand(service_type):
            del_ondemand_public_ip(vca_client, gateway, ctx.target.instance.runtime_properties[PUBLIC_IP], ctx)
        del ctx.target.instance.runtime_properties[PUBLIC_IP]


def _add_nat_rule(gateway, vca_client, rule_type, original_ip, translated_ip):
    any_type = None

    if rule_type == "DNAT":
        any_type = "Any"

    ctx.logger.info("Create floating ip NAT rule: original_ip '{0}',"
                    "translated_ip '{1}', rule type '{2}'"
                    .format(original_ip, translated_ip, rule_type))

    gateway.add_nat_rule(
        rule_type, original_ip, any_type, translated_ip, any_type, any_type)


def _del_nat_rule(gateway, vca_client, rule_type, original_ip, translated_ip):
    any_type = 'any'

    if rule_type == "DNAT":
        any_type = "Any"

    ctx.logger.info("Delete floating ip NAT rule: original_ip '{0}',"
                    "translated_ip '{1}', rule type '{2}'"
                    .format(original_ip, translated_ip, rule_type))

    gateway.del_nat_rule(
        rule_type, original_ip, any_type, translated_ip, any_type, any_type)
