import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
from network_plugin import public_nat
import network_plugin
import vcloud_plugin_common
from IPy import IP


class NetworkPluginPublicNatMockTestCase(test_mock_base.TestBase):

    def test_is_rule_exists(self):
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', '22', 'internal', '11', 'TCP'
        )
        # exist
        self.assertTrue(
            public_nat._is_rule_exists(
                [rule_inlist], 'SNAT', 'external', '22', 'internal',
                '11', 'TCP')
        )
        # not exist
        self.assertFalse(
            public_nat._is_rule_exists(
                [rule_inlist], 'SNAT', 'external', '22', 'internal',
                '11', 'UDP')
        )

    def test_get_original_port_for_delete(self):
        # no replacement
        fake_ctx = self.generate_relation_context()
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.1", "11"),
                "11"
            )
        # replacement for other
        fake_ctx = self.generate_relation_context()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {
                ("10.1.1.2", "11"): '12'
            }
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.1", "11"),
                "11"
            )
        # replacement for other
        fake_ctx = self.generate_relation_context()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {
                ("10.1.1.2", "11"): '12'
            }
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_delete("10.1.1.2", "11"),
                "12"
            )

    def test_get_original_port_for_create(self):
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        # exeption about same port
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._get_original_port_for_create(
                gateway, 'SNAT', 'external', 'any', 'internal', '11', 'TCP'
            )
        # everythiong fine with different port
        self.assertEqual(
            public_nat._get_original_port_for_create(
                gateway, 'SNAT', 'external', 'any', 'internal', '12', 'TCP'
            ),
            'any'
        )
        # relink some port to other
        # port have not used yet
        self.assertEqual(
            public_nat._get_original_port_for_create(
                gateway, 'SNAT', 'external', 10, 'internal', '12', 'TCP'
            ),
            10
        )

    def test_get_original_port_for_create_with_ctx(self):
        # with replace, but without replace table - up port +1
        fake_ctx = self.generate_relation_context()
        fake_ctx._target.instance.runtime_properties = {
            public_nat.PORT_REPLACEMENT: {}
        }
        gateway = mock.Mock()
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', 10, 'internal', 11, 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external', '10', 'internal', '11', 'TCP'
                ),
                11
            )
            self.assertEqual(
                fake_ctx._target.instance.runtime_properties,
                {
                    public_nat.PORT_REPLACEMENT:  {
                        ('external', '10'): 11
                    }
                }
            )
        # same but without replacement at all
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.assertEqual(
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external', '10', 'internal', '11', 'TCP'
                ),
                11
            )
            self.assertEqual(
                fake_ctx._target.instance.runtime_properties,
                {
                    public_nat.PORT_REPLACEMENT: {
                        ('external', '10'): 11
                    }
                }
            )
        # we dont have enought ports
        rule_inlist = self.generate_nat_rule(
            'SNAT', 'external', public_nat.MAX_PORT_NUMBER,
            'internal', 11, 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(return_value=[rule_inlist])
        fake_ctx._target.instance.runtime_properties = {}
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat._get_original_port_for_create(
                    gateway, 'SNAT', 'external',
                    public_nat.MAX_PORT_NUMBER, 'internal', '11', 'TCP'
                )

    def test_get_gateway_ip_range(self):
        gate = mock.Mock()
        # empty list of networks
        gate.get_dhcp_pools = mock.MagicMock(return_value=[])
        self.assertEqual(
            public_nat._get_gateway_ip_range(gate, 'something'),
            None
        )
        # exist other network
        gate.get_dhcp_pools = mock.MagicMock(return_value=[
            self.genarate_pool(
                'test_network', '127.0.0.1', '127.0.0.255'
            )
        ])
        self.assertEqual(
            public_nat._get_gateway_ip_range(gate, 'something'),
            None
        )
        # exist correct network
        self.assertEqual(
            public_nat._get_gateway_ip_range(gate, 'test_network'),
            (IP('127.0.0.1'), IP('127.0.0.255'))
        )

    def test_obtain_public_ip(self):
        fake_ctx = self.generate_relation_context()
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        gateway = mock.Mock()
        vca_client = mock.Mock()
        # exist some ip for delete
        self.assertEqual(
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, network_plugin.DELETE
            ),
            '192.168.1.1'
        )
        # no ip for delete
        fake_ctx._target.instance.runtime_properties = {}
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, network_plugin.DELETE
            )
        # unknow operation
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, 'unknow operation'
            )
        # exist some public ip
        fake_ctx._target.node.properties = {
            'nat': {
                network_plugin.PUBLIC_IP: '192.168.1.1'
            }
        }
        self.assertEqual(
            public_nat._obtain_public_ip(
                vca_client, fake_ctx, gateway, network_plugin.CREATE
            ),
            '192.168.1.1'
        )
        # no public ip yet
        fake_ctx._target.node.properties = {
            'nat': {}
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'vdc': 'vdc_name',
                'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            }
        }
        gateway.get_public_ips = mock.MagicMock(return_value=[
            '10.18.1.1', '10.18.1.2'
        ])
        rule_inlist = self.generate_nat_rule(
            'DNAT', '10.18.1.1', 'any', 'internal', '11', 'TCP'
        )
        gateway.get_nat_rules = mock.MagicMock(
            return_value=[rule_inlist]
        )
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                self.assertEqual(
                    public_nat._obtain_public_ip(
                        vca_client, fake_ctx, gateway,
                        network_plugin.CREATE
                    ),
                    '10.18.1.2'
                )

    def test_get_network_ip_range(self):
        # dont have ip range for this network
        vca_client = self.generate_client()
        self.assertEqual(
            public_nat._get_network_ip_range(
                vca_client, "some_org", "some_network"
            ),
            None
        )
        vca_client.get_networks.assert_called_with("some_org")
        # different network
        network = self.gen_vca_client_network(
            name="some", start_ip="127.1.1.1", end_ip="127.1.1.255"
        )
        vca_client.get_networks = mock.MagicMock(return_value=[network])
        self.assertEqual(
            public_nat._get_network_ip_range(
                vca_client, "some_org", "some_network"
            ),
            None
        )
        # correct network name
        vca_client.get_networks = mock.MagicMock(return_value=[network])
        self.assertEqual(
            public_nat._get_network_ip_range(
                vca_client, "some_org", "some"
            ),
            (IP('127.1.1.1'), IP('127.1.1.255'))
        )

    def test_create_ip_range(self):
        # context
        fake_ctx = self.generate_relation_context()
        fake_ctx._source.instance.runtime_properties = {
            network_plugin.network.VCLOUD_NETWORK_NAME: "some"
        }
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'org': 'some_org'
            }
        }
        fake_ctx._target.instance.runtime_properties = {}
        # vca client
        vca_client = self.generate_client()
        # gateway
        gate = vca_client._vdc_gateway
        gate.get_dhcp_pools = mock.MagicMock(return_value=[])
        network = self.gen_vca_client_network(
            name="some", start_ip="127.1.1.100", end_ip="127.1.1.200"
        )
        vca_client.get_networks = mock.MagicMock(return_value=[network])
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                # empty gateway dhcp pool
                # vca pool: 127.1.1.100..127.1.1.200
                self.assertEqual(
                    public_nat._create_ip_range(vca_client, gate),
                    '127.1.1.100 - 127.1.1.200'
                )
                vca_client.get_networks.assert_called_with("some_org")
                # network from gate
                gate.get_dhcp_pools = mock.MagicMock(return_value=[
                    self.genarate_pool(
                        "some", '127.1.1.1', '127.1.1.255'
                    )
                ])
                self.assertEqual(
                    public_nat._create_ip_range(vca_client, gate),
                    '127.1.1.1 - 127.1.1.255'
                )
                # network not exist
                network = self.gen_vca_client_network(
                    name="other", start_ip="127.1.1.100",
                    end_ip="127.1.1.200"
                )
                vca_client.get_networks = mock.MagicMock(
                    return_value=[network]
                )
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat._create_ip_range(vca_client, gate)

    def test_save_configuration(self):

        def _context_for_delete(service_type):
            """
                create correct context for delete
            """
            fake_ctx = self.generate_relation_context()
            self.set_services_conf_result(
                gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            fake_ctx._target.instance.runtime_properties = {
                network_plugin.PUBLIC_IP: "1.2.3.4"
            }
            properties = {
                'vcloud_config': {
                    'org': 'some_org',
                }
            }
            if service_type:
                properties['vcloud_config']['service_type'] = service_type
            fake_ctx._source.node.properties = properties
            return fake_ctx

        def _ip_exist_in_runtime(fake_ctx):
            """
                ip still exist in ctx
            """
            runtime_properties = fake_ctx._target.instance.runtime_properties
            return network_plugin.PUBLIC_IP in runtime_properties

        vca_client = self.generate_client()
        gateway = vca_client._vdc_gateway
        # cant save configuration: server busy
        self.set_services_conf_result(
            gateway, None
        )
        self.set_gateway_busy(gateway)
        fake_ctx = self.generate_relation_context()
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            self.prepare_retry(fake_ctx)
            public_nat._save_configuration(
                gateway, vca_client, "any", "any"
            )
            self.check_retry_realy_called(fake_ctx)
        # operation create
        fake_ctx = self.generate_relation_context()
        self.set_services_conf_result(
            gateway, vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            # success save configuration
            public_nat._save_configuration(
                gateway, vca_client, network_plugin.CREATE, "1.2.3.4"
            )
            self.assertEqual(
                fake_ctx._target.instance.runtime_properties,
                {
                    network_plugin.PUBLIC_IP: "1.2.3.4"
                }
            )
        # delete - subscription service
        fake_ctx = _context_for_delete(
            vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
        )
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, vca_client, network_plugin.DELETE, "1.2.3.4"
                )

        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        # delete - without service
        fake_ctx = _context_for_delete(None)
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, vca_client, network_plugin.DELETE, "1.2.3.4"
                )

        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        # delete - ondemand service - nat
        fake_ctx = _context_for_delete(
            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'nat': {
                network_plugin.PUBLIC_IP: "1.2.3.4"
            }
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, vca_client, network_plugin.DELETE, "1.2.3.4"
                )

        self.assertFalse(_ip_exist_in_runtime(fake_ctx))
        # delete - ondemand - not nat
        gateway.deallocate_public_ip = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        fake_ctx = _context_for_delete(
            vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
        )
        fake_ctx._target.node.properties = {
            'nat': {}
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat._save_configuration(
                    gateway, vca_client, network_plugin.DELETE, "1.2.3.4"
                )
        gateway.deallocate_public_ip.assert_called_with("1.2.3.4")
        self.assertFalse(_ip_exist_in_runtime(fake_ctx))

    def test_nat_network_operation(self):
        vca_client = self.generate_client()
        gateway = vca_client._vdc_gateway
        # used wrong operation
        with self.assertRaises(cfy_exc.NonRecoverableError):
            public_nat.nat_network_operation(
                vca_client, gateway, "unknow", "DNAT", "1.2.3.4",
                "2.3.4.5", "11", "11", "TCP"
            )
        # run correct operation/rule
        fake_ctx = self.generate_relation_context()
        for operation in [network_plugin.DELETE, network_plugin.CREATE]:
            for rule_type in ["SNAT", "DNAT"]:
                with mock.patch(
                    'network_plugin.public_nat.ctx', fake_ctx
                ):
                    with mock.patch(
                        'vcloud_plugin_common.ctx', fake_ctx
                    ):
                        public_nat.nat_network_operation(
                            vca_client, gateway, operation, rule_type,
                            "1.2.3.4", "2.3.4.5", "11", "11", "TCP"
                        )
                if rule_type == "DNAT":
                    if operation == network_plugin.DELETE:
                        gateway.del_nat_rule.assert_called_with(
                            'DNAT', '1.2.3.4', '11', '2.3.4.5', '11',
                            'TCP'
                        )
                    else:
                        gateway.add_nat_rule.assert_called_with(
                            'DNAT', '1.2.3.4', '11', '2.3.4.5', '11',
                            'TCP'
                        )
                else:
                    if operation == network_plugin.DELETE:
                        gateway.del_nat_rule.assert_called_with(
                            'SNAT', '2.3.4.5', 'any', '1.2.3.4', 'any',
                            'any'
                        )
                    else:
                        gateway.add_nat_rule.assert_called_with(
                            'SNAT', '2.3.4.5', 'any', '1.2.3.4', 'any',
                            'any'
                        )

    def test_prepare_server_operation(self):

        def _generate_client_and_context():
            vca_client = self.generate_client(vms_networks=[{
                'is_connected': True,
                'network_name': 'network_name',
                'is_primary': True,
                'ip': '1.1.1.1'
            }])
            self.set_network_routed_in_client(vca_client)
            fake_ctx = self.generate_relation_context()
            fake_ctx._target.node.properties = {
                'nat': {
                    'edge_gateway': 'gateway'
                }
            }
            fake_ctx._source.node.properties = {
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                }
            }
            fake_ctx._target.instance.runtime_properties = {
                network_plugin.PUBLIC_IP: '192.168.1.1'
            }
            self.set_services_conf_result(
                vca_client._vdc_gateway,
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            return vca_client, fake_ctx

        vca_client, fake_ctx = _generate_client_and_context()
        # no rules for update
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat.prepare_server_operation(
                        vca_client, network_plugin.DELETE
                    )
        # with some rules
        vca_client, fake_ctx = _generate_client_and_context()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT',
                'protocol': 'TCP',
                'original_port': "11",
                'translated_port': "11"
            }]
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_server_operation(
                    vca_client, network_plugin.DELETE
                )
        vca_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', '11', '1.1.1.1', '11', 'TCP'
        )
        # with default value
        vca_client, fake_ctx = _generate_client_and_context()
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.PUBLIC_IP: '192.168.1.1'
        }
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_server_operation(
                    vca_client, network_plugin.DELETE
                )
        vca_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', 'any', '1.1.1.1', 'any', 'any'
        )

    def test_prepare_network_operation(self):

        def _generate_client_and_context():
            vca_client = self.generate_client(vms_networks=[{
                'is_connected': True,
                'network_name': 'network_name',
                'is_primary': True,
                'ip': '1.1.1.1'
            }])
            self.set_network_routed_in_client(vca_client)
            gate = vca_client._vdc_gateway
            gate.get_dhcp_pools = mock.MagicMock(return_value=[])
            network = self.gen_vca_client_network(
                name="some", start_ip="127.1.1.100", end_ip="127.1.1.200"
            )
            vca_client.get_networks = mock.MagicMock(return_value=[network])
            self.set_services_conf_result(
                vca_client._vdc_gateway,
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
            # ctx
            fake_ctx = self.generate_relation_context()
            fake_ctx._source.instance.runtime_properties = {
                network_plugin.network.VCLOUD_NETWORK_NAME: "some"
            }
            fake_ctx._source.node.properties = {
                'vcloud_config': {
                    'org': 'some_org',
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                }
            }
            fake_ctx._target.node.properties = {
                'nat': {
                    'edge_gateway': 'gateway'
                }
            }
            fake_ctx._target.instance.runtime_properties = {
                network_plugin.PUBLIC_IP: '192.168.1.1'
            }
            return vca_client, fake_ctx
        # no rules
        vca_client, fake_ctx = _generate_client_and_context()
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    public_nat.prepare_network_operation(
                        vca_client, network_plugin.DELETE
                    )
        # rules with default values
        vca_client, fake_ctx = _generate_client_and_context()
        fake_ctx._target.node.properties = {
            'nat': {
                'edge_gateway': 'gateway'
            },
            'rules': [{
                'type': 'DNAT'
            }]
        }
        with mock.patch(
            'network_plugin.public_nat.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                public_nat.prepare_network_operation(
                    vca_client, network_plugin.DELETE
                )
        vca_client._vdc_gateway.del_nat_rule.assert_called_with(
            'DNAT', '192.168.1.1', 'any', '127.1.1.100 - 127.1.1.200',
            'any', 'any'
        )

    def test_creation_validation(self):
        fake_client = self.generate_client()
        # no nat
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # no gateway
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                },
                'nat': {
                    'some_field': 'something'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # wrong ip
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: 'any'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # no free ip
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # no rules
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: '10.12.2.1'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # wrong protocol
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "some"
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # wrong original_port
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "TCP",
                    'original_port': 'some'
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)

        # wrong original_port
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "TCP",
                    'original_port': 11,
                    'translated_port': 'some'
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                public_nat.creation_validation(ctx=fake_ctx)
        # fine
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name',
                    'service_type': vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
                },
                'nat': {
                    'edge_gateway': 'gateway',
                    network_plugin.PUBLIC_IP: '10.12.2.1'
                },
                'rules': [{
                    'type': 'DNAT',
                    'protocol': "TCP",
                    'original_port': 11,
                    'translated_port': 12
                }]
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            public_nat.creation_validation(ctx=fake_ctx)

if __name__ == '__main__':
    unittest.main()
