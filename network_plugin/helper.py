from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import OrgVdcNetworkType, ReferenceType, NetworkConfigurationType, IpScopesType, IpScopeType, IpRangesType, IpRangeType
from pyvcloud.helper import generalHelperFunctions as ghf
import requests

def create(vcd_client, network_name):
    content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
    namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5"'

    vdc = vcd_client._get_vdc()

    gateway = ReferenceType(href=vcd_client.get_gateways()[0].me.href)
    gateway.original_tagname_ = "EdgeGateway"

    iprange = IpRangeType(StartAddress="192.168.0.100", EndAddress="192.168.0.199")
    ipranges = IpRangesType(IpRange=[iprange])

    ipscope = IpScopeType(IsInherited=False, Gateway="192.168.0.1", Netmask="255.255.255.0",
                          Dns1="4.2.2.4", DnsSuffix="example.com", IpRanges=ipranges)
    ipscopes = IpScopesType(IpScope=[ipscope])

    configuration = NetworkConfigurationType(IpScopes=ipscopes, FenceMode="natRouted")

    net = OrgVdcNetworkType(name=network_name, Description="test_network", EdgeGateway=gateway, Configuration=configuration, IsShared=False)

    body = '<?xml version="1.0" encoding="UTF-8"?>{0}'.format(ghf.convertPythonObjToStr(net, name='OrgVdcNetwork', namespacedef=namespacedef))

    postlink = filter(lambda link: link.get_type() == content_type, vdc.get_Link())[0].href
    headers = vcd_client._get_vcdHeaders()
    headers["Content-Type"] = content_type
    response = requests.post(postlink, data=body, headers=headers)
    if response.status_code == requests.codes.created:
        task = taskType.parseString(response.content, True)
        return (True, task)
    else:
        return (False, response.content)


if __name__ == '__main__':
    from vcloud_plugin_common import VcloudDirectorClient    
    vcd_client = VcloudDirectorClient().get()
    print create(vcd_client, "testnet")    
