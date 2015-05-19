import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
from network_plugin import security_group
import vcloud_plugin_common


class NetworkPluginSecurityGroupMockTestCase(test_mock_base.TestBase):

    def test_get_gateway_name_from_params(self):
        self.assertEqual(
            security_group._get_gateway_name({
                'security_group': {
                    'edge_gateway': 'some_edge_gateway'
                }
            }),
            'some_edge_gateway'
        )

    def test_get_gateway_name_from_ctx(self):
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'edge_gateway': 'some_edge_gateway'
                }
            }
        )
        with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
            self.assertEqual(
                security_group._get_gateway_name({
                    'security_group': {}
                }),
                'some_edge_gateway'
            )

    def generate_context_for_security_group(self):
        fake_ctx = self.generate_relation_context()
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'edge_gateway': 'some_edge_gateway',
                'vdc': 'vdc_name'
            }
        }
        return fake_ctx

    def check_rule_operation(self, rule_type, rules, vms_networks=None):
        if not vms_networks:
            vms_networks = []
        fake_client = self.generate_client(vms_networks=vms_networks)
        fake_ctx = self.generate_context_for_security_group()
        fake_ctx._target.node.properties = {
            'rules': rules
        }
        # any calls for save configuration will be success
        gateway = fake_client._vdc_gateway
        self.set_services_conf_result(
            gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        # for check calls for add/delete rule
        gateway.add_fw_rule = mock.MagicMock(return_value=None)
        gateway.delete_fw_rule = mock.MagicMock(return_value=None)
        # any networks will be routed
        self.set_network_routed_in_client(fake_client)
        with mock.patch('network_plugin.security_group.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                security_group._rule_operation(
                    rule_type, fake_client
                )
        return gateway

    def check_rule_operation_fail(self, rule_type, rules):
        fake_client = self.generate_client()
        fake_ctx = self.generate_context_for_security_group()
        fake_ctx._target.node.properties = {
            'rules': rules
        }
        # check busy
        gateway = fake_client._vdc_gateway
        self.set_gateway_busy(gateway)
        self.prepare_retry(fake_ctx)
        self.set_services_conf_result(
            fake_client._vdc_gateway, None
        )
        with mock.patch('network_plugin.security_group.ctx', fake_ctx):
            with mock.patch('vcloud_plugin_common.ctx', fake_ctx):
                security_group._rule_operation(
                    rule_type, fake_client
                )

        self.check_retry_realy_called(fake_ctx)

    def test_rule_operation_empty_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            gateway = self.check_rule_operation(rule_type, [])
            gateway.save_services_configuration.assert_called_once_with()
            self.check_rule_operation_fail(rule_type, [])
            self.assertFalse(gateway.add_fw_rule.called)
            self.assertFalse(gateway.delete_fw_rule.called)

    def test_rule_operation_default_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            gateway = self.check_rule_operation(rule_type, [{}])
            gateway.save_services_configuration.assert_called_once_with()
            if rule_type == security_group.CREATE_RULE:
                gateway.add_fw_rule.assert_called_once_with(
                    True, 'Rule added by pyvcloud', 'allow', 'Any',
                    'Any', 'External', 'Any', 'External', False
                )
                self.assertFalse(gateway.delete_fw_rule.called)
            else:
                gateway.delete_fw_rule.assert_called_once_with(
                    'Any', 'Any', 'external', 'Any', 'external'
                )
                self.assertFalse(gateway.add_fw_rule.called)
            self.check_rule_operation_fail(rule_type, [{}])

    def test_rule_operation_internal_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            rules = [
                {
                    'description': 'description',
                    'source_ip': 'internal',
                    'source_port': 22,
                    "destination": 'internal',
                    'destination_port': 40,
                    'protocol': 'tcp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            gateway = self.check_rule_operation(rule_type, rules)
            gateway.save_services_configuration.assert_called_once_with()
            if rule_type == security_group.CREATE_RULE:
                gateway.add_fw_rule.assert_called_once_with(
                    True, 'description', 'deny', 'Tcp', '40',
                    'Internal', '22', 'External', True
                )
                self.assertFalse(gateway.delete_fw_rule.called)
            else:
                gateway.delete_fw_rule.assert_called_once_with(
                    'Tcp', '40', 'internal', '22', 'external'
                )
                self.assertFalse(gateway.add_fw_rule.called)
            self.check_rule_operation_fail(rule_type, rules)

    def test_rule_operation_icmp_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            rules = [
                {
                    'description': 'ip',
                    'source': '1.2.3.4',
                    'source_port': 60,
                    "destination": '5.6.7.8',
                    'destination_port': 22,
                    'protocol': 'icmp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            gateway = self.check_rule_operation(rule_type, rules)
            gateway.save_services_configuration.assert_called_once_with()
            if rule_type == security_group.CREATE_RULE:
                gateway.add_fw_rule.assert_called_once_with(
                    True, 'ip', 'deny', 'Icmp', '22', '5.6.7.8',
                    '60', '1.2.3.4', True
                )
                self.assertFalse(gateway.delete_fw_rule.called)
            else:
                gateway.delete_fw_rule.assert_called_once_with(
                    'Icmp', '22', '5.6.7.8', '60', '1.2.3.4'
                )
                self.assertFalse(gateway.add_fw_rule.called)
            self.check_rule_operation_fail(rule_type, rules)

    def test_rule_operation_tcp_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            rules = [
                {
                    'description': 'ip',
                    'source': '1.2.3.4',
                    'source_port': 60,
                    'destination': '5.6.7.8',
                    'destination_port': 22,
                    'protocol': 'tcp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            gateway = self.check_rule_operation(rule_type, rules)
            gateway.save_services_configuration.assert_called_once_with()
            if rule_type == security_group.CREATE_RULE:
                gateway.add_fw_rule.assert_called_once_with(
                    True, 'ip', 'deny', 'Tcp', '22', '5.6.7.8', '60',
                    '1.2.3.4', True
                )
                self.assertFalse(gateway.delete_fw_rule.called)
            else:
                gateway.delete_fw_rule.assert_called_once_with(
                    'Tcp', '22', '5.6.7.8', '60', '1.2.3.4'
                )
                self.assertFalse(gateway.add_fw_rule.called)
            self.check_rule_operation_fail(rule_type, rules)

    def test_rule_operation_host_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            # source
            rules = [
                {
                    'description': 'ip',
                    'source': 'host',
                    'source_port': 60,
                    'destination': '5.6.7.8',
                    'destination_port': 22,
                    'protocol': 'tcp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            gateway = self.check_rule_operation(
                rule_type, rules,
                [{
                    'is_connected': True,
                    'network_name': 'network_name',
                    'is_primary': True,
                    'ip': '1.1.1.1'
                }]
            )
            gateway.save_services_configuration.assert_called_once_with()
            if rule_type == security_group.CREATE_RULE:
                gateway.add_fw_rule.assert_called_once_with(
                    True, 'ip', 'deny', 'Tcp', '22', '5.6.7.8', '60',
                    '1.1.1.1', True
                )
                self.assertFalse(gateway.delete_fw_rule.called)
            else:
                gateway.delete_fw_rule.assert_called_once_with(
                    'Tcp', '22', '5.6.7.8', '60', '1.1.1.1'
                )
                self.assertFalse(gateway.add_fw_rule.called)
            # destination
            rules = [
                {
                    'description': 'ip',
                    'source': '1.2.3.4',
                    'source_port': 60,
                    'destination': 'host',
                    'destination_port': 22,
                    'protocol': 'tcp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            gateway = self.check_rule_operation(
                rule_type, rules,
                [{
                    'is_connected': True,
                    'is_primary': True,
                    'network_name': 'network_name',
                    'ip': '1.1.1.1'
                }]
            )
            gateway.save_services_configuration.assert_called_once_with()
            if rule_type == security_group.CREATE_RULE:
                gateway.add_fw_rule.assert_called_once_with(
                    True, 'ip', 'deny', 'Tcp', '22', '1.1.1.1', '60',
                    '1.2.3.4', True
                )
                self.assertFalse(gateway.delete_fw_rule.called)
            else:
                gateway.delete_fw_rule.assert_called_once_with(
                    'Tcp', '22', '1.1.1.1', '60', '1.2.3.4'
                )
                self.assertFalse(gateway.add_fw_rule.called)

    def test_rule_operation_error_ip_rule(self):
        for rule_type in [
            security_group.CREATE_RULE, security_group.DELETE_RULE
        ]:
            rules = [
                {
                    'description': 'ip',
                    'source': '300.1.3.4',
                    'source_port': 60,
                    'destination': '5.6.7.8',
                    'destination_port': 22,
                    'protocol': 'tcp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_rule_operation(rule_type, rules)
            rules = [
                {
                    'description': 'ip',
                    'source': '2.1.3.4',
                    'source_port': 60,
                    'destination': '5.6.7.300',
                    'destination_port': 22,
                    'protocol': 'tcp',
                    'action': 'deny',
                    'log_traffic': True
                }
            ]
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_rule_operation(rule_type, rules)

    def test_create(self):
        fake_ctx = self.generate_context_for_security_group()
        fake_client = self.generate_client()
        # empty rules list
        fake_ctx._target.node.properties = {
            'rules': []
        }
        self.set_services_conf_result(
            fake_client._vdc_gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            security_group.create(ctx=fake_ctx)

    def test_delete(self):
        fake_ctx = self.generate_context_for_security_group()
        fake_client = self.generate_client()
        # empty rules list
        fake_ctx._target.node.properties = {
            'rules': []
        }
        self.set_services_conf_result(
            fake_client._vdc_gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            security_group.delete(ctx=fake_ctx)

    def check_creation_validation(self, rule):
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'vcloud_config': {
                        'edge_gateway': 'some_edge_gateway',
                        'vdc': 'vdc_name'
                    },
                    'rules': [rule]
                }
            )
            security_group.creation_validation(ctx=fake_ctx)

    def test_creation_validation(self):
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            fake_ctx = self.generate_node_context(
                properties={
                    'vcloud_config': {
                        'edge_gateway': 'some_edge_gateway',
                        'vdc': 'vdc_name'
                    }
                }
            )
            fake_client._vdc_gateway.is_fw_enabled = mock.MagicMock(
                return_value=False
            )
            #  Gateway firewall is disabled
            with self.assertRaises(cfy_exc.NonRecoverableError):
                security_group.creation_validation(ctx=fake_ctx)
            fake_client._vdc_gateway.is_fw_enabled = mock.MagicMock(
                return_value=True
            )
            # no rules
            with self.assertRaises(cfy_exc.NonRecoverableError):
                security_group.creation_validation(ctx=fake_ctx)
            # wrong description
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 10
                })
            # wrong source
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": 11
                })
            with self.assertRaises(cfy_exc.NonRecoverableError):
                security_group.creation_validation(ctx=fake_ctx)
            # wrong ip
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.1111'
                })
            # wrong port
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234
                })
            # wrong destination
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234,
                    "destination": 123
                })
            # wrong destination ip
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234,
                    "destination": "123.1"
                })
            # wrong destination_port
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234,
                    "destination": "123.12.1.1",
                    'destination_port': 1111111
                })
            # wrong protocol
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234,
                    "destination": "123.12.1.1",
                    'destination_port': 1111,
                    "protocol": 'someone'
                })
            # wrong action
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234,
                    "destination": "123.12.1.1",
                    'destination_port': 1111,
                    "protocol": 'any',
                    "action": 'some'
                })
            # wrong action
            with self.assertRaises(cfy_exc.NonRecoverableError):
                self.check_creation_validation({
                    "description": 'a',
                    "source": '1.2.3.11',
                    "source_port": 1234,
                    "destination": "123.12.1.1",
                    'destination_port': 1111,
                    "protocol": 'any',
                    "action": 'allow',
                    'log_traffic': 'somevalue'
                })
            # correct
            self.check_creation_validation({
                "description": 'a',
                "source": '1.2.3.11',
                "source_port": 1234,
                "destination": "123.12.1.1",
                'destination_port': 1111,
                "protocol": 'any',
                "action": 'allow',
                'log_traffic': True
            })
            self.check_creation_validation({
                "description": 'a',
                "source": '1.2.3.11',
                "source_port": 1234,
                "destination": "123.12.1.1",
                'destination_port': 1111,
                "protocol": 'any',
                "action": 'allow',
                'log_traffic': False
            })
            self.check_creation_validation({
                "action": 'allow'
            })


if __name__ == '__main__':
    unittest.main()
