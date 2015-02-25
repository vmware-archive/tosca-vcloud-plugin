from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config
from network_plugin import check_ip, isExternalIpAssigned, isInternalIpAssigned, collectAssignedIps, get_vm_ip, save_gateway_configuration
from network_plugin import CREATE, DELETE


PUBLIC_IP = 'public_ip'


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

    gateway = vca_client.get_gateway(get_vcloud_config()['vdc'],
                                     ctx.target.node.properties['floatingip']['edge_gateway'])
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
        if not public_ip:
            public_ip = getFreeIP(gateway)
            ctx.logger.info("Assign external IP {0}".format(public_ip))

        if isInternalIpAssigned(internal_ip, gateway):
            raise cfy_exc.NonRecoverableError(
                "VM private IP {0} already has public ip assigned ".format(internal_ip))

        if isExternalIpAssigned(public_ip, gateway):
            raise cfy_exc.NonRecoverableError(
                "Rule with IP: {0} already exists".format(public_ip))

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


def getFreeIP(gateway):
    public_ips = set(gateway.get_public_ips())
    allocated_ips = set([address.external for address in collectAssignedIps(gateway)])
    available_ips = public_ips - allocated_ips
    if not available_ips:
        raise cfy_exc.NonRecoverableError(
            "Can't get external IP address")
    return list(available_ips)[0]
