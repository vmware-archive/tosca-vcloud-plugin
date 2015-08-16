from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (with_vca_client, get_vcloud_config,
                                  is_subscription, is_ondemand, get_mandatory)
from network_plugin import (check_ip, CheckAssignedExternalIp,
                            CheckAssignedInternalIp, get_vm_ip,
                            save_gateway_configuration, getFreeIP,
                            CREATE, DELETE, PUBLIC_IP, get_gateway,
                            get_public_ip, del_ondemand_public_ip,
                            set_retry)


@operation
@with_vca_client
def connect_floatingip(vca_client, **kwargs):
    """
        create new floating ip for node
    """
    if not _floatingip_operation(CREATE, vca_client, ctx):
        return set_retry(ctx)


@operation
@with_vca_client
def disconnect_floatingip(vca_client, **kwargs):
    """
        release floating ip
    """
    if not _floatingip_operation(DELETE, vca_client, ctx):
        return set_retry(ctx)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """
        validate node context,
        fields from floatingip dict:
        * edge_gateway - mandatory,
        * public_ip - prefered ip for node, can be empty
        fields from vcloud_config:
        * service_type - ondemand, subscription
        also check availability of public ip if set or exist some free
        ip in subscription case
    """
    floatingip = get_mandatory(ctx.node.properties, 'floatingip')
    edge_gateway = get_mandatory(floatingip, 'edge_gateway')
    gateway = get_gateway(vca_client, edge_gateway)
    service_type = get_vcloud_config().get('service_type')
    public_ip = floatingip.get(PUBLIC_IP)
    if public_ip:
        check_ip(public_ip)
        CheckAssignedExternalIp(public_ip, gateway)
    else:
        if is_subscription(service_type):
            getFreeIP(gateway)


def _floatingip_operation(operation, vca_client, ctx):
    """
        create/release floating ip by nat rules for this ip with
        relation to internal ip for current node,
        save selected public_ip in runtime properties
    """
    service_type = get_vcloud_config().get('service_type')
    gateway = get_gateway(
        vca_client, ctx.target.node.properties['floatingip']['edge_gateway'])
    if gateway.is_busy():
        return False
    internal_ip = get_vm_ip(vca_client, ctx, gateway)

    nat_operation = None
    public_ip = (ctx.target.instance.runtime_properties.get(PUBLIC_IP)
                 or ctx.target.node.properties['floatingip'].get(PUBLIC_IP))
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
            "Unknown operation {0}".format(operation)
        )

    external_ip = check_ip(public_ip)

    nat_operation(gateway, "SNAT", internal_ip, external_ip)
    nat_operation(gateway, "DNAT", external_ip, internal_ip)
    success = save_gateway_configuration(gateway, vca_client)
    if not success:
        return False
    if operation == CREATE:
        ctx.target.instance.runtime_properties[PUBLIC_IP] = external_ip
        ctx.source.instance.runtime_properties['ssh_port'] = str(22)
        ctx.source.instance.runtime_properties['ssh_public_ip'] = external_ip            

    else:
        if is_ondemand(service_type):
            if not ctx.target.node.properties['floatingip'].get(PUBLIC_IP):
                del_ondemand_public_ip(
                    vca_client,
                    gateway,
                    ctx.target.instance.runtime_properties[PUBLIC_IP],
                    ctx)
        del ctx.target.instance.runtime_properties[PUBLIC_IP]
        del ctx.source.instance.runtime_properties['ssh_port']
        del ctx.source.instance.runtime_properties['ssh_public_ip']
    return True


def _add_nat_rule(gateway, rule_type, original_ip, translated_ip):
    """
        add nat rule with enable any types of trafic from translated_ip
        to origin_ip
    """
    any_type = "any"

    ctx.logger.info("Create floating ip NAT rule: original_ip '{0}',"
                    "translated_ip '{1}', rule type '{2}'"
                    .format(original_ip, translated_ip, rule_type))

    gateway.add_nat_rule(
        rule_type, original_ip, any_type, translated_ip, any_type, any_type)


def _del_nat_rule(gateway, rule_type, original_ip, translated_ip):
    """
        drop rule created by add_nat_rule
    """
    any_type = 'any'

    ctx.logger.info("Delete floating ip NAT rule: original_ip '{0}',"
                    "translated_ip '{1}', rule type '{2}'"
                    .format(original_ip, translated_ip, rule_type))

    gateway.del_nat_rule(
        rule_type, original_ip, any_type, translated_ip, any_type, any_type)
