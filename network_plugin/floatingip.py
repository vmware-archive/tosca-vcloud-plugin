from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import wait_for_task, with_vca_client, get_vcloud_config, SUBSCRIPTION_SERVICE_TYPE
from network_plugin import check_ip, isExternalIpAssigned, isInternalIpAssigned, get_vm_ip, save_gateway_configuration, getFreeIP, CREATE, DELETE, PUBLIC_IP


@operation
@with_vca_client
def connect_floatingip(vca_client, **kwargs):
    _floatingip_operation(CREATE, vca_client, ctx)


@operation
@with_vca_client
def disconnect_floatingip(vca_client, **kwargs):
    _floatingip_operation(DELETE, vca_client, ctx)


def _floatingip_operation(operation, vca_client, ctx):

    def showMessage(message, ip):
        ctx.logger.info(message.format(ip))
    service_type = get_vcloud_config().get('service_type')
    if isSubscription(service_type):
        gateway = vca_client.get_gateway(get_vcloud_config()['vdc'],
                                         ctx.target.node.properties['floatingip']['edge_gateway'])
    else:
        gateway = vca_client.get_gateways(get_vcloud_config()['vdc'])[0]

    if not gateway:
        raise cfy_exc.NonRecoverableError("Gateway not found")

    internal_ip = check_ip(get_vm_ip(vca_client, ctx))

    nat_operation = None
    public_ip = None
    if PUBLIC_IP in ctx.target.instance.runtime_properties:
        public_ip = ctx.target.instance.runtime_properties[PUBLIC_IP]
    elif PUBLIC_IP in ctx.target.node.properties['floatingip']:
        public_ip = ctx.target.node.properties['floatingip'][PUBLIC_IP]
    if operation == CREATE:
        if isInternalIpAssigned(internal_ip, gateway):
            raise cfy_exc.NonRecoverableError(
                "VM private IP {0} already has public ip assigned ".format(internal_ip))

        if isSubscription(service_type):
            if not public_ip:
                public_ip = getFreeIP(gateway)
                ctx.logger.info("Assign external IP {0}".format(public_ip))

            if isExternalIpAssigned(public_ip, gateway):
                raise cfy_exc.NonRecoverableError(
                    "Rule with IP: {0} already exists".format(public_ip))
        else:
            public_ip = get_ondemand_public_ip(vca_client, gateway)

        nat_operation = _add_nat_rule
    elif operation == DELETE:
        if not isExternalIpAssigned(public_ip, gateway):
            showMessage("Rule with IP: {0} absent", public_ip)
            return
        elif not public_ip:
            showMessage("Can't get external IP", public_ip)
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
        if not isSubscription(service_type):
            del_ondemand_public_ip(vca_client, gateway, ctx.target.instance.runtime_properties[PUBLIC_IP])
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


def get_ondemand_public_ip(vca_client, gateway):
    old_public_ips = set(gateway.get_public_ips())
    task = gateway.allocate_public_ip()
    if task:
        wait_for_task(vca_client, task)
    else:
        raise cfy_exc.NonRecoverableError("Can't get public ip for ondemand service")
    # update gateway for new IP address
    gateway = vca_client.get_gateways(get_vcloud_config()['vdc'])[0]
    new_public_ips = set(gateway.get_public_ips())
    new_ip = new_public_ips - old_public_ips
    if new_ip:
        ctx.logger.info("Assign public IP {0}".format(new_ip))
    else:
        raise cfy_exc.NonRecoverableError(
            "Can't get new public IP address")
    return list(new_ip)[0]


def del_ondemand_public_ip(vca_client, gateway, ip):
    task = gateway.deallocate_public_ip(ip)
    if task:
        wait_for_task(vca_client, task)
        ctx.logger.info("Public IP {0} deallocated".format(ip))
    else:
        raise cfy_exc.NonRecoverableError("Can't deallocate public ip {0} for ondemand service".format(ip))


def isSubscription(service_type):
    return not service_type or service_type == SUBSCRIPTION_SERVICE_TYPE
