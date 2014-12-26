from cloudify import exceptions as cfy_exc
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType, networkType, queryRecordViewType
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


def delete (vcd_client, network_name):
    try:
        vdc = vcd_client._get_vdc()        
        headers = vcd_client._get_vcdHeaders()            
        netref = _get_network_ref(vdc, headers, network_name)
        if not netref:
            raise ValueError
        response = requests.delete(netref, headers=headers)
        if response.status_code == requests.codes.accepted:
            task = taskType.parseString(response.content, True)
            return (True, task)
        else:
            return (False, response.content)
    except ValueError:
        raise cfy_exc.NonRecoverableError("Could not get network")        
    except IndexError:
        raise cfy_exc.NonRecoverableError("Could not get network")

def _get_network_ref(vdc, headers, name):
    link = filter(lambda link: link.get_rel() == "orgVdcNetworks", vdc.get_Link())
    response = requests.get(link[0].get_href(), headers = headers)
    queryResultRecords = queryRecordViewType.parseString(response.content, True)
    if response.status_code == requests.codes.ok:    
        for record in queryResultRecords.get_Record():
            if record.name == name:
                return record.href
    
    
if __name__ == '__main__':
    name = "testnet"
    from vcloud_plugin_common import VcloudDirectorClient    
    vcd_client = VcloudDirectorClient().get()
    
