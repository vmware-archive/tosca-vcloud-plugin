from cloudify import exceptions as cfy_exc
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType,\
    queryRecordViewType, networkType
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import OrgVdcNetworkType,\
    ReferenceType, NetworkConfigurationType, IpScopesType, IpScopeType,\
    IpRangesType, IpRangeType, DhcpPoolServiceType
from pyvcloud.helper import generalHelperFunctions as ghf

import pyvcloud.vclouddirector
import pyvcloud.gateway
import requests

DEFAULT_LEASE = 3600
MAX_LEASE = 7200


class ProxyGateway(pyvcloud.gateway.Gateway):
    def get_dhcp_pools(self):
        gatewayConfiguration = self.me.get_Configuration()
        edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
        dhcpService = filter(lambda service: service.__class__.__name__ == "GatewayDhcpServiceType",
                             edgeGatewayServiceConfiguration.get_NetworkService())[0]
        return dhcpService.get_Pool()

    def _post_configuration(self):
        import pdb; pdb.set_trace()
        gatewayConfiguration = self.me.get_Configuration()
        edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
        body = '<?xml version="1.0" encoding="UTF-8"?>' + \
               ghf.convertPythonObjToStr(edgeGatewayServiceConfiguration, name='EdgeGatewayServiceConfiguration',
                                         namespacedef='xmlns="http://www.vmware.com/vcloud/v1.5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ')
        content_type = "application/vnd.vmware.admin.edgeGatewayServiceConfiguration+xml"
        link = filter(lambda link: link.get_type() == content_type, self.me.get_Link())
        content_type = "application/vnd.vmware.admin.edgeGatewayServiceConfiguration+xml"
        self.headers["Content-Type"] = content_type
        response = requests.post(link[0].get_href(), data=body, headers=self.headers)
        if response.status_code == requests.codes.accepted:
            task = taskType.parseString(response.content, True)
            return (True, task)
        else:
            return (False, response.content)

    def _post_dhcp_pools(self, pools):
        gatewayConfiguration = self.me.get_Configuration()
        edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
        dhcpService = filter(lambda service: service.__class__.__name__ == "GatewayDhcpServiceType",
                             edgeGatewayServiceConfiguration.get_NetworkService())[0]
        dhcpService.set_Pool(pools)
        return self._post_configuration()

    def add_dhcp_pool(self, network_name, low_ip_address, hight_ip_address,
                      default_lease, max_lease):
        if not default_lease:
            default_lease = DEFAULT_LEASE
        if not max_lease:
            max_lease = MAX_LEASE
        gatewayConfiguration = self.me.get_Configuration()
        network = filter(lambda interface: interface.get_Name() == network_name,
                         gatewayConfiguration.get_GatewayInterfaces().get_GatewayInterface())[0].get_Network()
        network.set_type("application/vnd.vmware.vcloud.orgVdcNetwork+xml")

        new_pool = DhcpPoolServiceType(IsEnabled=True, Network=network, DefaultLeaseTime=default_lease,
                                       MaxLeaseTime=max_lease,
                                       LowIpAddress=low_ip_address,
                                       HighIpAddress=hight_ip_address)
        pools = self.get_dhcp_pools()
        pools.append(new_pool)
        return self._post_dhcp_pools(pools)

    def delete_dhcp_pool(self, network_name):
        pools = [p for p in self.get_dhcp_pools() if p.get_Network().name != network_name]
        return self._post_dhcp_pools(pools)

    def _getFirewallService(self):
        gatewayConfiguration = self.me.get_Configuration()
        edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
        return filter(lambda service: service.__class__.__name__ == "FirewallServiceType",
                      edgeGatewayServiceConfiguration.get_NetworkService())[0]

    def _post_firewall_rules(self, rules):
        self._getFirewallService().set_FirewallRule(rules)
        return self._post_configuration()

    def get_fw_rules(self):
        return self._getFirewallService().get_FirewallRule()

    def add_fw_rule(self):
        rules = self.get_fw_rules()
        return self._post_firewall_rules(rules)


class ProxyVCD(pyvcloud.vclouddirector.VCD):
    def __init__(self, vcd_client):
        super(ProxyVCD, self).__init__(vcd_client.token, vcd_client.href,
                                       vcd_client.version, vcd_client.service,
                                       vcd_client.vdc)

    def get_gateway(self, gatewayId):
        gateway = super(ProxyVCD, self).get_gateway(gatewayId)
        if gateway:
            # replace type with own implementation
            gateway.__class__ = ProxyGateway
        return gateway

    def get_admin_network_href(self, network_name):
        vdc = self._get_vdc()
        link = filter(lambda link: link.get_rel() == "orgVdcNetworks",
                      vdc.get_Link())
        response = requests.get(link[0].get_href(), headers=self.headers)
        queryResultRecords = queryRecordViewType.parseString(response.content,
                                                             True)
        if response.status_code == requests.codes.ok:
            for record in queryResultRecords.get_Record():
                if record.name == network_name:
                    return record.href

    def create_vdc_network(self, network_name, gateway_name, start_address,
                           end_address, gateway_ip, netmask,
                           dns1, dns2, dns_suffix):
        vdc = self._get_vdc()
        gateway = ReferenceType(href=self.get_gateway(gateway_name).me.href)
        gateway.original_tagname_ = "EdgeGateway"

        iprange = IpRangeType(StartAddress=start_address,
                              EndAddress=end_address)
        ipranges = IpRangesType(IpRange=[iprange])
        ipscope = IpScopeType(IsInherited=False,
                              Gateway=gateway_ip,
                              Netmask=netmask,
                              Dns1=dns1,
                              Dns2=dns2,
                              DnsSuffix=dns_suffix,
                              IpRanges=ipranges)
        ipscopes = IpScopesType(IpScope=[ipscope])

        configuration = NetworkConfigurationType(IpScopes=ipscopes,
                                                 FenceMode="natRouted")
        net = OrgVdcNetworkType(name=network_name, Description="Network reated by pyvcloud",
                                EdgeGateway=gateway, Configuration=configuration,
                                IsShared=False)
        namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5"'
        content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
        body = '<?xml version="1.0" encoding="UTF-8"?>{0}'.format(
            ghf.convertPythonObjToStr(net, name='OrgVdcNetwork',
                                      namespacedef=namespacedef))
        postlink = filter(lambda link: link.get_type() == content_type,
                          vdc.get_Link())[0].href
        headers = self.headers
        headers["Content-Type"] = content_type
        response = requests.post(postlink, data=body, headers=headers)
        if response.status_code == requests.codes.created:
            network = networkType.parseString(response.content, True)
            task = network.get_Tasks().get_Task()[0]
            return (True, task)
        else:
            return (False, response.content)

    def delete_vdc_network(self, network_name):
        netref = self.get_admin_network_href(network_name)
        response = requests.delete(netref, headers=self.headers)
        if response.status_code == requests.codes.accepted:
            task = taskType.parseString(response.content, True)
            return (True, task)
        else:
            return (False, response.content)

        raise cfy_exc.NonRecoverableError("Could not get network")
