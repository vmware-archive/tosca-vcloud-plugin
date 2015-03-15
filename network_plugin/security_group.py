from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_vcloud_config
from network_plugin import check_ip, get_vm_ip, save_gateway_configuration


CREATE_RULE = 1
DELETE_RULE = 2


@operation
@with_vca_client
def create(vca_client, **kwargs):
    _rule_operation(CREATE_RULE, vca_client)


@operation
@with_vca_client
def delete(vca_client, **kwargs):
    _rule_operation(DELETE_RULE, vca_client)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    pass


def _rule_operation(operation, vca_client):
    gateway = vca_client.get_gateway(get_vcloud_config()['vdc'],
                                         ctx.target.node.properties['security_group'].get(
                                             'edge_gateway', get_vcloud_config()['vdc']))
    if not gateway:
        raise cfy_exc.NonRecoverableError("Gateway not found")
    protocol = _check_protocol(ctx.target.node.properties['rules']['protocol'])
    dest_port = str(ctx.target.node.properties['rules']['port'])
    description = ctx.target.node.properties['rules']['description']
    dest_ip = check_ip(get_vm_ip(vca_client, ctx))
    if operation == CREATE_RULE:
        gateway.add_fw_rule(True, description, "allow", protocol, dest_port, dest_ip,
                            "Any", "External", False)
        error_message = "Could not add firewall rule: {0}".format(description)
        ctx.logger.info("Firewall rule has been created {0}".format(description))

    if operation == DELETE_RULE:
        gateway.delete_fw_rule(protocol, dest_port, dest_ip,
                               "Any", "external")
        error_message = "Could not delete firewall rule: {0}".format(description)
        ctx.logger.info("Firewall rule has been deleted {0}".format(description))
    save_gateway_configuration(gateway, vca_client, error_message)


def _check_protocol(protocol):
    valid_protocols = ["Tcp", "Udp", "Icmp", "Any"]
    protocol = protocol.capitalize()
    if protocol not in valid_protocols:
        raise cfy_exc.NonRecoverableError(
            "Unknown protocol: {0}. Valid protocols are: {1}".format(protocol, valid_protocols))
    return protocol
