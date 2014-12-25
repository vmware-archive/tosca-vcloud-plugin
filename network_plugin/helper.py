from vcloud_plugin_common import Config, VcloudDirectorClient
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import OrgVdcNetworkType, ReferenceType, NetworkConfigurationType, IpScopesType, IpScopeType, IpRangesType, IpRangeType
from pyvcloud.helper import generalHelperFunctions as ghf

testnet = "test_network"

content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
vcd_client = VcloudDirectorClient().get()
vdc=vcd_client._get_vdc()
networks_name = [net.name for net in  vdc.AvailableNetworks.Network]

postlink = filter(lambda link: link.get_type() == content_type, vdc.get_Link())[0].href

gatewayref = vcd_client.get_gateways()[0].me.href

gateway=ReferenceType(href=gatewayref)
gateway.original_tagname_="EdgeGateway"

iprange = IpRangeType(StartAddress="192.168.0.100", EndAddress="192.168.0.199")
ipranges = IpRangesType(IpRange=[iprange])
ipscope = IpScopeType(IsInherited=False, Gateway="192.168.0.1", Netmask="255.255.255.0",
                    Dns1="4.2.2.4", DnsSuffix="example.com", IpRanges=ipranges)
ipscopes =  IpScopesType(IpScope=[ipscope])
configuration = NetworkConfigurationType(IpScopes=ipscopes, FenceMode="natRouted")
net = OrgVdcNetworkType(name=testnet, Description="test_network", EdgeGateway=gateway, Configuration=configuration, IsShared=True)
body = '<?xml version="1.0" encoding="UTF-8"?>' + \
       ghf.convertPythonObjToStr(net, name = 'OrgVdcNetwork',\
                                 namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5"')
print body
#response = requests.post(postlink.get_href(), data=body, headers=self.headers)
#print response.status_code
