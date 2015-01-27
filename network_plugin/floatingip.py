from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vcd_client, wait_for_task
from network_plugin import check_ip, isExternalIpAssigned, isInternalIpAssigned, collectAssignedIps, get_vm_ip


CREATE = 1
DELETE = 2
PUBLIC_IP = 'public_ip'


@operation
@with_vcd_client
def connect_floatingip(vcd_client, **kwargs):
    _floatingip_operation(CREATE, vcd_client, ctx)


@operation
@with_vcd_client
def disconnect_floatingip(vcd_client, **kwargs):
    _floatingip_operation(DELETE, vcd_client, ctx)


def _floatingip_operation(operation, vcd_client, ctx):
    def showMessage(message, ip):
        ctx.logger.info(message.format(ip))

    gateway = vcd_client.get_gateway(
        ctx.node.properties['floatingip']['gateway'])
    if not gateway:
        raise cfy_exc.NonRecoverableError("Gateway not found")

    internal_ip = check_ip(get_vm_ip(vcd_client, ctx))

    function = None
    description = None
    public_ip = None
    if PUBLIC_IP in ctx.instance.runtime_properties:
        public_ip = ctx.instance.runtime_properties[PUBLIC_IP]
    elif PUBLIC_IP in ctx.node.properties['floatingip']:
        public_ip = ctx.node.properties['floatingip'][PUBLIC_IP]

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

        function = gateway.add_nat_rule
        description = "create"
    elif operation == DELETE:
        if not isExternalIpAssigned(public_ip, gateway):
            showMessage("Rule with IP: {0} absent", public_ip)
            return
        elif not public_ip:
            showMessage("Can't get external IP", public_ip)
            return

        function = gateway.del_nat_rule
        description = "delete"
    else:
        raise cfy_exc.NonRecoverableError(
            "Unknown operation {0}").format(operation)

    external_ip = check_ip(public_ip)

    _nat_operation(function, description, vcd_client, "SNAT",
                   internal_ip, external_ip)
    _nat_operation(function, description, vcd_client, "DNAT",
                   external_ip, internal_ip)

    if operation == CREATE:
        ctx.instance.runtime_properties[PUBLIC_IP] = external_ip
    else:
        del ctx.instance.runtime_properties[PUBLIC_IP]


def _nat_operation(function, description, vcd_client,
                   rule_type, original_ip, translated_ip):
    any_type = None

    if rule_type == "DNAT":
        any_type = "Any"

    ctx.logger.info("{0} floating ip NAT rule: original_ip '{1}',"
                    "translated_ip '{2}', rule type '{3}'"
                    .format(description, original_ip,
                            translated_ip, rule_type))

    success, result, _ = function(rule_type, original_ip, any_type,
                                translated_ip, any_type, any_type)
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not {0} {1} rule: {2}"
            .format(description, rule_type, result))
    wait_for_task(vcd_client, result)


def getFreeIP(gateway):
    public_ips = set(gateway.get_public_ips())
    allocated_ips = set([address.external for address in collectAssignedIps(gateway)])
    available_ips = public_ips - allocated_ips
    if not available_ips:
        raise cfy_exc.NonRecoverableError(
            "Can't get external IP address")
    return list(available_ips)[0]
