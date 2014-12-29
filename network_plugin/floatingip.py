from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from IPy import IP
from vcloud_plugin_common import with_vcd_client, wait_for_task

CREATE = 1
DELETE = 2
VCLOUD_VAPP_NAME = 'vcloud_vapp_name'


@operation
@with_vcd_client
def connect_floatingip(vcd_client, **kwargs):
    _floatingip_operation(vcd_client, ctx, CREATE)


@operation
@with_vcd_client
def disconnect_floatingip(vcd_client, **kwargs):
    _floatingip_operation(vcd_client, ctx, DELETE)


def _check_ip(address):
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addres: {0}".format(address))
    return address


def _get_vapp_list(relationships):
    return [relationship.target for relationship in relationships
            if VCLOUD_VAPP_NAME
            in relationship.target.instance.runtime_properties]


def _get_vm_ip(vcd_client, ctx):
    try:
        vappName = _get_vapp_list(
            ctx.instance.relationships)[0][VCLOUD_VAPP_NAME]
        vapp = vcd_client.get_vApp(vappName)
        if not vapp:
            raise cfy_exc.NonRecoverableError("Could not find vApp")
        vm_info = vapp.get_vms_network_info()
        # assume that we have 1 vm per vApp with minium 1 connection
        connection = vm_info[0][0]
        if connection['is_connected']:
            return connection['ip']
        else:
            raise cfy_exc.NonRecoverableError("Network not connected")
    except IndexError:
        raise cfy_exc.NonRecoverableError("Could not get vm IP address")


def _nat_operation(vcd_client, gateway, rule_type, original_ip, translated_ip,
                   operation):
    function = None
    operation_description = None
    any_type = None

    if rule_type == "DNAT":
        any_type = "Any"

    if operation == CREATE:
        function = gateway.add_nat_rule
        operation_description = "create"
    elif operation == DELETE:
        function = gateway.del_nat_rule
        operation_description = "delete"
    else:
        cfy_exc.NonRecoverableError("Unknown operation")

    success, task, _ = function(rule_type, original_ip, any_type,
                                translated_ip, any_type, any_type)
    if not success:
        raise cfy_exc.NonRecoverableError(
            "Could not {0} {1} rule").format(operation_description, rule_type)
    wait_for_task(vcd_client, task)


def _floatingip_operation(vcd_client, ctx, operation):
    gateway = vcd_client.get_gateway(
        ctx.target.node.properties['floatingip']['gateway'])
    if gateway:
        external_ip = _check_ip(
            ctx.target.node.properties['floatingip']['public_ip'])
        internal_ip = _check_ip(_get_vm_ip(vcd_client, ctx))
        _nat_operation(vcd_client, gateway, "SNAT", internal_ip, external_ip,
                       operation)
        _nat_operation(vcd_client, gateway, "DNAT", external_ip, internal_ip,
                       operation)
    else:
        raise cfy_exc.NonRecoverableError("Gateway not found")
