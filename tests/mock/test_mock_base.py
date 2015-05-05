import mock
import unittest
from cloudify import mocks as cfy_mocks


class TestBase(unittest.TestCase):

    ERROR_PLACE = "ERROR_MESSAGE_PLACE_HOLDER"

    def generate_task(self, status):
        task = mock.Mock()
        error = mock.Mock()
        error.get_message = mock.MagicMock(return_value="Some Error")
        task.get_Error = mock.MagicMock(return_value=error)
        task.get_status = mock.MagicMock(return_value=status)
        return task

    def gen_network(self, fenceMode):
        network_config = mock.Mock()
        network_config.get_FenceMode = mock.MagicMock(
            return_value=fenceMode
        )
        network = mock.Mock()
        network.get_Configuration = mock.MagicMock(
            return_value=network_config
        )
        return network

    def generate_client(self, vms_networks=None, vdc_networks=None):

        def _gen_network(vdc_name, network_name):
            return self.gen_network(network_name)

        def _get_admin_network_href(vdc_name, network_name):
            return "_href" + network_name

        def _get_gateway(vdc_name="vdc"):
            gate = mock.Mock()
            pool = mock.Mock()
            network = mock.Mock()
            network.get_href = mock.MagicMock(
                return_value="_href" + vdc_name
            )
            pool.get_Network = mock.MagicMock(return_value=network)
            gate.get_dhcp_pools = mock.MagicMock(return_value=[pool])
            gate.add_dhcp_pool = mock.MagicMock(return_value=None)
            gate.save_services_configuration = mock.MagicMock(
                return_value=None
            )
            gate.response = mock.Mock()
            gate.response.content = ('''
                    <?xml version="1.0" encoding="UTF-8"?>
                    <Error
                        xmlns="http://www.vmware.com/vcloud/v1.5"
                        status="stoped"
                        name="error"
                        message="''' + self.ERROR_PLACE + '''"
                    />''').replace("\n", " ").strip()
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
            gate.is_fw_enabled = mock.MagicMock(return_value=True)
            return gate

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
        client.get_network = _gen_network
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

    def generate_context(
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

        relationship = mock.Mock()
        relationship.target = mock.Mock()
        relationship.target.node = mock.Mock()
        relationship.target.node.properties = relation_node_properties
        fake_ctx.instance._relationships = [relationship]

        return fake_ctx
