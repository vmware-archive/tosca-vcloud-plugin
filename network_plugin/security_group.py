from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_mandatory
from network_plugin import check_ip, get_vm_ip, save_gateway_configuration, check_protocol, get_gateway


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
    security_group = get_mandatory(ctx.node.properties, 'security_group')
    get_gateway(vca_client, security_group.get('edge_gateway'))
    rules = get_mandatory(ctx.node.properties, 'rules')
    for rule in rules:
        check_protocol(rule.get('protocol', "Any"))
        dest_port = rule.get('port')
        if dest_port and not isinstance(dest_port, int):
            raise cfy_exc.NonRecoverableError("Parameter 'port' must be integer")


def _rule_operation(operation, vca_client):
    gateway = get_gateway(vca_client,
                          ctx.target.node.properties['security_group'].get('edge_gateway'))
    for rule in ctx.target.node.properties['rules']:
        protocol = check_protocol(rule.get('protocol', "Any"))
        dest_port = str(rule['port'])
        description = rule['description']
        dest_ip = check_ip(get_vm_ip(vca_client, ctx))
        if operation == CREATE_RULE:
            gateway.add_fw_rule(True, description, "allow", protocol, dest_port, dest_ip,
                                "Any", "External", False)
            error_message = "Could not add firewall rule: {0}".format(description)
            ctx.logger.info("Firewall rule has been created {0}".format(description))
        elif operation == DELETE_RULE:
            gateway.delete_fw_rule(protocol, dest_port, dest_ip,
                                   "Any", "external")
            error_message = "Could not delete firewall rule: {0}".format(description)
            ctx.logger.info("Firewall rule has been deleted {0}".format(description))
    save_gateway_configuration(gateway, vca_client, error_message)
