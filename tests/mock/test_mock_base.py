import mock
import unittest
from cloudify import mocks as cfy_mocks
from network_plugin import BUSY_MESSAGE, NAT_ROUTED


class TestBase(unittest.TestCase):

    ERROR_PLACE = "ERROR_MESSAGE_PLACE_HOLDER"

    def generate_task(self, status):
        task = mock.Mock()
        error = mock.Mock()
        error.get_message = mock.MagicMock(return_value="Some Error")
        task.get_Error = mock.MagicMock(return_value=error)
        task.get_status = mock.MagicMock(return_value=status)
        return task

    def set_services_conf_result(self, gateway, result):
        """
            set result for save configuration
        """
        task = None
        if result:
            task = self.generate_task(result)
        gateway.save_services_configuration = mock.MagicMock(
            return_value=task
        )

    def set_gateway_busy(self, gateway):
        message = gateway.response.content
        message = message.replace(
            self.ERROR_PLACE, BUSY_MESSAGE
        )
        gateway.response.content = message

    def prepare_retry(self, ctx):
        """
            set fake retry operation
        """
        ctx.operation.retry = mock.MagicMock(
            return_value=None
        )

    def check_retry_realy_called(self, ctx):
        """
            check that we really call retry
        """
        ctx.operation.retry.assert_called_with(
            message='Waiting for gateway.',
            retry_after=10
        )

    def generate_gateway(
        self, vdc_name="vdc", vms_networks=None, vdc_networks=None
    ):
        gate = mock.Mock()
        gate.get_dhcp_pools = mock.MagicMock(return_value=[
            self.genarate_pool(
                vdc_name, '127.0.0.1', '127.0.0.255'
            )
        ])
        gate.add_dhcp_pool = mock.MagicMock(return_value=None)
        self.set_services_conf_result(gate, None)
        gate.response = mock.Mock()
        gate.response.content = ('''
                <?xml version="1.0" encoding="UTF-8"?>
                <Error
                    xmlns="http://www.vmware.com/vcloud/v1.5"
                    status="stoped"
                    name="error"
                    message="''' + self.ERROR_PLACE + '''"
                />''').replace("\n", " ").strip()
        # list of interfaces
        interfaces = []
        if vms_networks:
            for network in vms_networks:
                interface = mock.Mock()
                interface.get_Name = mock.MagicMock(
                    return_value=network.get(
                        'network_name', 'unknowNet'
                    )
                )
                interfaces.append(interface)
        gate.get_interfaces = mock.MagicMock(
            return_value=interfaces
        )
        # firewall enabled
        gate.is_fw_enabled = mock.MagicMock(return_value=True)
        # dont have any nat rules
        gate.get_nat_rules = mock.MagicMock(return_value=[])
        # cant deallocate ip
        gate.deallocate_public_ip = mock.MagicMock(return_value=None)
        # public ips not exist
        gate.get_public_ips = mock.MagicMock(return_value=[])
        return gate

    def generate_fake_client_network(
        self, fenceMode=None, name="some", start_ip="127.1.1.1",
        end_ip="127.1.1.255"
    ):
        """
            generate network for vca client
        """
        network = mock.Mock()
        # generate ip
        network._ip = mock.Mock()
        network._ip.get_StartAddress = mock.MagicMock(return_value=start_ip)
        network._ip.get_EndAddress = mock.MagicMock(return_value=end_ip)
        # generate ipRange
        network._ip_range = mock.Mock()
        network._ip_range.IpRanges.IpRange = [network._ip]
        # network get_network_configuration
        network._network_config = mock.Mock()
        network._network_config.get_FenceMode = mock.MagicMock(
            return_value=fenceMode
        )
        # network scope
        network.Configuration.IpScopes.IpScope = [network._ip_range]
        # network
        network.get_name = mock.MagicMock(return_value=name)
        network.get_Configuration = mock.MagicMock(
            return_value=network._network_config
        )
        return network

    def generate_nat_rule(
        self, rule_type, original_ip, original_port, translated_ip,
        translated_port, protocol
    ):
        rule = mock.Mock()
        rule.get_OriginalIp = mock.MagicMock(return_value=original_ip)
        rule.get_OriginalPort = mock.MagicMock(return_value=original_port)
        rule.get_TranslatedIp = mock.MagicMock(return_value=translated_ip)
        rule.get_TranslatedPort = mock.MagicMock(return_value=translated_port)
        rule.get_Protocol = mock.MagicMock(return_value=protocol)
        rule_inlist = mock.Mock()
        rule_inlist.get_RuleType = mock.MagicMock(return_value=rule_type)
        rule_inlist.get_GatewayNatRule = mock.MagicMock(return_value=rule)
        return rule_inlist

    def genarate_pool(self, name, low_ip, high_ip):
        pool = mock.Mock()
        pool.Network = mock.Mock()
        pool.Network.name = name
        pool.get_LowIpAddress = mock.MagicMock(return_value=low_ip)
        pool.get_HighIpAddress = mock.MagicMock(return_value=high_ip)
        # network in pool
        network = mock.Mock()
        network.get_href = mock.MagicMock(
            return_value="_href" + name
        )
        pool.get_Network = mock.MagicMock(return_value=network)
        return pool

    def set_network_routed_in_client(self, fake_client):
        """
            set any network as routed
        """
        network = self.generate_fake_client_network(NAT_ROUTED)
        fake_client.get_network = mock.MagicMock(return_value=network)

    def generate_client(self, vms_networks=None, vdc_networks=None):

        def _generate_fake_client_network(vdc_name, network_name):
            return self.generate_fake_client_network(network_name)

        def _get_admin_network_href(vdc_name, network_name):
            return "_href" + network_name

        def _get_gateway(vdc_name="vdc"):
            return self.generate_gateway(
                vdc_name,
                vms_networks,
                vdc_networks
            )

        def _get_gateways(vdc_name):
            return [_get_gateway(vdc_name)]

        def _get_vdc(networks):
            vdc = mock.Mock()
            vdc.AvailableNetworks = mock.Mock()
            vdc.AvailableNetworks.Network = []
            if networks:
                for net in networks:
                    networkEntity = mock.Mock()
                    networkEntity.name = net
                    vdc.AvailableNetworks.Network.append(networkEntity)
            return vdc

        template = mock.Mock()
        template.get_name = mock.MagicMock(return_value='secret')
        catalogItems = mock.Mock()
        catalogItems.get_CatalogItem = mock.MagicMock(
            return_value=[template]
        )
        catalog = mock.Mock()
        catalog.get_name = mock.MagicMock(return_value='public')
        catalog.get_CatalogItems = mock.MagicMock(
            return_value=catalogItems
        )
        client = mock.Mock()
        client.get_catalogs = mock.MagicMock(return_value=[catalog])
        client.get_network = _generate_fake_client_network
        client.get_networks = mock.MagicMock(return_value=[])
        client.get_admin_network_href = _get_admin_network_href
        client._vdc_gateway = _get_gateway()
        client.get_gateway = mock.MagicMock(
            return_value=client._vdc_gateway
        )
        client.get_gateways = _get_gateways
        client._vapp = self.generate_vapp(vms_networks)
        client.get_vapp = mock.MagicMock(return_value=client._vapp)
        client._app_vdc = _get_vdc(vdc_networks)
        client.get_vdc = mock.MagicMock(return_value=client._app_vdc)
        client.delete_vdc_network = mock.MagicMock(
            return_value=(False, None)
        )
        client.create_vdc_network = mock.MagicMock(
            return_value=(False, None)
        )
        return client

    def generate_vca(self):
        return mock.MagicMock(return_value=self.generate_client())

    def generate_vapp(self, vms_networks=None):

        def _get_vms_network_info():
            return [vms_networks]

        vapp = mock.Mock()
        vapp.me = mock.Mock()
        vapp.get_vms_network_info = _get_vms_network_info
        return vapp

    def generate_relation_context(self):
        source = mock.Mock()
        source.node = mock.Mock()
        target = mock.Mock()
        target.node = mock.Mock()
        target.instance.runtime_properties = {}
        fake_ctx = cfy_mocks.MockCloudifyContext(
            source=source, target=target
        )
        return fake_ctx

    def generate_node_context(
        self, relation_node_properties=None, properties=None,
        runtime_properties=None
    ):

        class MockInstanceContext(cfy_mocks.MockNodeInstanceContext):

            self._relationships = None

            @property
            def relationships(self):
                return self._relationships

        if not properties:
            properties = {
                'management_network': '_management_network',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        if not runtime_properties:
            runtime_properties = {
                'vcloud_vapp_name': 'vapp_name'
            }
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties=properties,
            provider_context={},
            runtime_properties=runtime_properties
        )

        fake_ctx._instance = MockInstanceContext(
            fake_ctx.instance._id, fake_ctx.instance._runtime_properties
        )

        relationship = self.generate_relation_context()
        relationship._target.node.properties = relation_node_properties
        fake_ctx.instance._relationships = [relationship]

        return fake_ctx
