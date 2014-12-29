from cloudify import exceptions as cfy_exc
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType,\
    queryRecordViewType, networkType
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import OrgVdcNetworkType,\
    ReferenceType, NetworkConfigurationType, IpScopesType, IpScopeType,\
    IpRangesType, IpRangeType
from pyvcloud.helper import generalHelperFunctions as ghf
import requests
from network_plugin import check_ip

# draft implementation of missed method for network manipulations in pyvcloud
def create(vcd_client, network_name, properties):
    # gataway name not used, becouse there is only one gateway
    # properties["use_gateway"]

    content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
    namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5"'

    vdc = vcd_client._get_vdc()

    gateway = ReferenceType(href=vcd_client.get_gateways()[0].me.href)
    gateway.original_tagname_ = "EdgeGateway"

    iprange = IpRangeType(StartAddress=check_ip(properties["start_address"]),
                          EndAddress=check_ip(properties["end_address"]))
    ipranges = IpRangesType(IpRange=[iprange])

    ipscope = IpScopeType(IsInherited=False, Gateway=check_ip(properties["gateway_ip"]),
                          Netmask=check_ip(properties["netmask"]),
                          Dns1=check_ip(properties["dns"]),
                          DnsSuffix=properties["dns_duffix"],
                          IpRanges=ipranges)
    ipscopes = IpScopesType(IpScope=[ipscope])

    configuration = NetworkConfigurationType(IpScopes=ipscopes,
                                             FenceMode="natRouted")

    net = OrgVdcNetworkType(name=network_name, Description="Cloudify network",
                            EdgeGateway=gateway, Configuration=configuration,
                            IsShared=False)

    body = '<?xml version="1.0" encoding="UTF-8"?>{0}'.format(
        ghf.convertPythonObjToStr(net, name='OrgVdcNetwork',
                                  namespacedef=namespacedef))

    postlink = filter(lambda link: link.get_type() == content_type,
                      vdc.get_Link())[0].href
    headers = vcd_client._get_vcdHeaders()
    headers["Content-Type"] = content_type
    response = requests.post(postlink, data=body, headers=headers)
    if response.status_code == requests.codes.created:
        network = networkType.parseString(response.content, True)
        task = network.get_Tasks().get_Task()[0]
        return (True, task)
    else:
        return (False, response.content)


def delete(vcd_client, network_name):
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
    link = filter(lambda link: link.get_rel() == "orgVdcNetworks",
                  vdc.get_Link())
    response = requests.get(link[0].get_href(), headers=headers)
    queryResultRecords = queryRecordViewType.parseString(response.content,
                                                         True)
    if response.status_code == requests.codes.ok:
        for record in queryResultRecords.get_Record():
            if record.name == name:
                return record.href
