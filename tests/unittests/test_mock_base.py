# Copyright (c) 2014-2020 Cloudify Platform Ltd. All rights reserved
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

import mock
import unittest
from cloudify import mocks as cfy_mocks
import vcloud_network_plugin
from cloudify.state import current_ctx
vcloud_network_plugin.GATEWAY_TRY_COUNT = 2
vcloud_network_plugin.GATEWAY_TIMEOUT = 1


class MockToscaCloudifyContext(cfy_mocks.MockCloudifyContext):
    """updated mock for use with tosca"""

    _local = False

    @property
    def local(self):
        return self._local

    _internal = None

    @property
    def internal(self):
        return self._internal

    _nodes = None

    @property
    def nodes(self):
        return self._nodes


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
            self.ERROR_PLACE, vcloud_network_plugin.BUSY_MESSAGE
        )
        gateway.response.content = message

    def prepare_retry(self, ctx):
        """
            set fake retry operation
        """
        ctx.operation.retry = mock.MagicMock(
            return_value=None
        )

    def check_retry_realy_called(self, ctx, message=None, timeout=None):
        """
            check that we really call retry
        """
        if not message:
            message = 'Waiting for gateway.'
        if not timeout:
            timeout = vcloud_network_plugin.GATEWAY_TIMEOUT
        ctx.operation.retry.assert_called_with(
            message=message,
            retry_after=timeout
        )

    def prepere_gatway_busy_retry(self, fake_client, fake_ctx):
        """any operation for save gateway settings will return False"""
        gateway = fake_client._vdc_gateway
        self.set_gateway_busy(gateway)
        self.set_services_conf_result(
            fake_client._vdc_gateway, None
        )
        self.prepare_retry(fake_ctx)

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
        gate.is_busy = mock.MagicMock(return_value=False)
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
        network = self.generate_fake_client_network(
            vcloud_network_plugin.NAT_ROUTED
        )
        fake_client.get_network = mock.MagicMock(return_value=network)

    def generate_fake_client_disk(self, name="some_disk"):
        """
            generate fake disk for fake client,
            have used in client.get_disks
        """
        disk = mock.Mock()
        disk.name = name
        return disk

    def generate_fake_client_disk_ref(self, name):
        """
            generate ref for disk,
            have used for client.get_diskRefs
        """
        ref = mock.Mock()
        ref.name = name
        return ref

    def generate_fake_vms_disk(self, name="some_disk"):
        """
            generate attached vms for disk,
            have used for client.get_disks
        """
        vms = mock.Mock()
        vms._disk = name
        return vms

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
        # disks for client
        client.add_disk = mock.MagicMock(
            return_value=(False, None)
        )
        client.get_disks = mock.MagicMock(return_value=[])
        client.add_disk = mock.MagicMock(
            return_value=(False, None)
        )
        client.delete_disk = mock.MagicMock(
            return_value=(False, None)
        )
        client.get_diskRefs = mock.MagicMock(return_value=[])
        # login authification
        client.login = mock.MagicMock(
            return_value=False
        )
        client.logout = mock.MagicMock(
            return_value=False
        )
        client.get_instances = mock.MagicMock(
            return_value=[]
        )
        client.login_to_instance = mock.MagicMock(
            return_value=False
        )
        client.login_to_org = mock.MagicMock(
            return_value=False
        )
        return client

    def generate_vca(self):
        return mock.MagicMock(return_value=self.generate_client())

    def generate_vapp(self, vms_networks=None):

        def _get_vms_network_info():
            if vms_networks:
                return [vms_networks]
            else:
                return [[]]

        vapp = mock.Mock()
        vapp.me = mock.Mock()
        vapp.get_vms_network_info = _get_vms_network_info
        # disk for vapp
        vapp.attach_disk_to_vm = mock.MagicMock(
            return_value=None
        )
        vapp.detach_disk_from_vm = mock.MagicMock(
            return_value=None
        )
        # mememory/cpu customize
        vapp.modify_vm_memory = mock.MagicMock(
            return_value=None
        )
        vapp.modify_vm_cpu = mock.MagicMock(
            return_value=None
        )
        vapp.modify_vm_name = mock.MagicMock(
            return_value=None
        )

        return vapp

    def generate_relation_context(self):
        source = mock.Mock()
        source.node = mock.Mock()
        source.node.properties = {}
        target = mock.Mock()
        target.node = mock.Mock()
        target.node.properties = {}
        target.instance.runtime_properties = {}
        fake_ctx = MockToscaCloudifyContext(
            source=source, target=target
        )
        return fake_ctx

    def generate_relation_context_with_current_ctx(self):
        # generate new relation context with save such context
        # to current context that requed by 3.4 cloudify common plugin
        # changes
        fake_ctx = self.generate_relation_context()
        current_ctx.set(fake_ctx)
        return fake_ctx

    def generate_node_context(
        self, relation_node_properties=None, properties=None,
        runtime_properties=None
    ):

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
        fake_ctx = MockToscaCloudifyContext(
            node_id='test',
            node_name='test',
            properties=properties,
            provider_context={},
            runtime_properties=runtime_properties
        )

        fake_ctx._instance = cfy_mocks.MockNodeInstanceContext(
            fake_ctx.instance.id, fake_ctx.instance.runtime_properties
        )

        relationship = self.generate_relation_context()
        relationship._target.node.properties = relation_node_properties
        fake_ctx.instance._relationships = [relationship]

        return fake_ctx

    def generate_node_context_with_current_ctx(
        self, relation_node_properties=None, properties=None,
        runtime_properties=None
    ):
        # generate new node context with save such context
        # to current context that requed by 3.4 cloudify common plugin
        # changes
        fake_ctx = self.generate_node_context(
            relation_node_properties, properties,
            runtime_properties
        )
        current_ctx.set(fake_ctx)
        return fake_ctx

    def tearDown(self):
        current_ctx.clear()
