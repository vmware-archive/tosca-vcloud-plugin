# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (with_vca_client, get_mandatory,
                                  get_vcloud_config)
from vcloud_network_plugin import (check_ip, get_vm_ip, save_gateway_configuration,
                                   get_gateway, utils, set_retry, lock_gateway)


CREATE_RULE = 1
DELETE_RULE = 2

ADDRESS_LITERALS = ("any", "internal", "external", "host")
ACTIONS = ("allow", "deny")


@operation
@with_vca_client
@lock_gateway
def create(vca_client, **kwargs):
    """
        create firewall rules for node
    """
    if not _rule_operation(CREATE_RULE, vca_client):
        return set_retry(ctx)


@operation
@with_vca_client
@lock_gateway
def delete(vca_client, **kwargs):
    """
        drop firewall rules for node
    """
    if not _rule_operation(DELETE_RULE, vca_client):
        return set_retry(ctx)


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """
        validate firewall rules for node
    """
    getaway = get_gateway(
        vca_client, _get_gateway_name(ctx.node.properties)
    )
    if not getaway.is_fw_enabled():
        raise cfy_exc.NonRecoverableError(
            "Gateway firewall is disabled. Please, enable firewall.")
    rules = get_mandatory(ctx.node.properties, 'rules')
    for rule in rules:
        description = rule.get("description")
        if description and not isinstance(description, basestring):
            raise cfy_exc.NonRecoverableError(
                "Parameter 'description' must be string.")

        source = rule.get("source")
        if source:
            if not isinstance(source, basestring):
                raise cfy_exc.NonRecoverableError(
                    "Parameter 'source' must be valid IP address string.")
            if not _is_literal_ip(source):
                check_ip(source)

        utils.check_port(rule.get('source_port'))

        destination = rule.get('destination')
        if destination:
            if not isinstance(destination, basestring):
                raise cfy_exc.NonRecoverableError(
                    "Parameter 'destination' must be valid IP address string.")
            if not _is_literal_ip(destination):
                check_ip(destination)

        utils.check_port(rule.get('destination_port'))

        utils.check_protocol(rule.get('protocol'))

        action = get_mandatory(rule, "action")
        if (
            not isinstance(action, basestring) or action.lower() not in ACTIONS
        ):
            raise cfy_exc.NonRecoverableError(
                "Action must be on of{0}.".format(ACTIONS))

        log = rule.get('log_traffic')
        if log and not isinstance(log, bool):
            raise cfy_exc.NonRecoverableError(
                "Parameter 'log_traffic' must be boolean.")


def _rule_operation(operation, vca_client):
    """
        create/delete firewall rules in gateway for current node
    """
    gateway_name = _get_gateway_name(ctx.target.node.properties)
    gateway = get_gateway(vca_client, gateway_name)
    for rule in ctx.target.node.properties['rules']:
        description = rule.get('description', "Rule added by pyvcloud").strip()
        source_ip = rule.get("source", "external")
        if not _is_literal_ip(source_ip):
            check_ip(source_ip)
        elif _is_host_ip(source_ip):
            source_ip = get_vm_ip(vca_client, ctx, gateway)
        source_port = str(rule.get("source_port", "any"))
        dest_ip = rule.get("destination", "external")
        if not _is_literal_ip(dest_ip):
            check_ip(dest_ip)
        elif _is_host_ip(dest_ip):
            dest_ip = get_vm_ip(vca_client, ctx, gateway)
        dest_port = str(rule.get('destination_port', 'any'))
        protocol = rule.get('protocol', 'any').capitalize()
        action = rule.get("action", "allow")
        log = rule.get('log_traffic', False)

        if operation == CREATE_RULE:
            gateway.add_fw_rule(
                True, description, action, protocol, dest_port, dest_ip,
                source_port, source_ip, log)
            ctx.logger.info(
                "Firewall rule has been created: {0}".format(description))
        elif operation == DELETE_RULE:
            gateway.delete_fw_rule(protocol, dest_port, dest_ip,
                                   source_port, source_ip)
            ctx.logger.info(
                "Firewall rule has been deleted: {0}".format(description))

    ctx.logger.info("Saving security group configuration")
    return save_gateway_configuration(gateway, vca_client, ctx)


def _get_gateway_name(properties):
    """
        return geteway for current node from vcloud config or security
        group settings
    """
    security_group = properties.get('security_group')
    if security_group and 'edge_gateway' in security_group:
        getaway_name = security_group.get('edge_gateway')
    else:
        getaway_name = get_vcloud_config()['edge_gateway']
    return getaway_name


def _is_literal_ip(ip):
    return ip.lower() in ADDRESS_LITERALS


def _is_host_ip(ip):
    return ip.lower() == "host"
