from cloudify import exceptions as cfy_exc
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import taskType,\
    queryRecordViewType, networkType
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import OrgVdcNetworkType,\
    ReferenceType, NetworkConfigurationType, IpScopesType, IpScopeType,\
    IpRangesType, IpRangeType, DhcpPoolServiceType
from pyvcloud.helper import generalHelperFunctions as ghf
import requests
from network_plugin import check_ip
import collections
from IPy import IP

DEFAULT_LEASE = 3600
MAX_LEASE = 7200


# draft implementation of missed method for network manipulations in pyvcloud
def create_network(vcd_client, network_name, properties):
    # gataway name not used, becouse there is only one gateway
    # properties["use_gateway"]

    content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
    namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5"'

    vdc = vcd_client._get_vdc()

    gateway = ReferenceType(href=vcd_client.get_gateways()[0].me.href)
    gateway.original_tagname_ = "EdgeGateway"
    ip = _split_adresses(properties['static_range'])
    iprange = IpRangeType(StartAddress=check_ip(ip.start),
                          EndAddress=check_ip(ip.end))
    ipranges = IpRangesType(IpRange=[iprange])

    ipscope = IpScopeType(IsInherited=False,
                          Gateway=check_ip(properties["gateway_ip"]),
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


def delete_network(vcd_client, network_name):
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


def dhcp_pool_operation(vcd_client, network_name, dhcp_settings, pool_operation):
    gateway = vcd_client.get_gateways()[0]
    if not gateway:
        raise cfy_exc.NonRecoverableError("Gateway not found")
    gatewayConfiguration = gateway.me.get_Configuration()
    edgeGatewayServiceConfiguration = gatewayConfiguration.get_EdgeGatewayServiceConfiguration()
    dhcpService = filter(lambda service: service.__class__.__name__ == "GatewayDhcpServiceType",
                         edgeGatewayServiceConfiguration.get_NetworkService())[0]

    network = filter(lambda interface: interface.get_Name() == network_name,
                     gatewayConfiguration.get_GatewayInterfaces().get_GatewayInterface())[0].get_Network()
    network.set_type("application/vnd.vmware.vcloud.orgVdcNetwork+xml")

    dhcpService.set_Pool(pool_operation(dhcpService.get_Pool(), network, dhcp_settings))

    body = '<?xml version="1.0" encoding="UTF-8"?>' + \
           ghf.convertPythonObjToStr(edgeGatewayServiceConfiguration, name='EdgeGatewayServiceConfiguration',
                                     namespacedef='xmlns="http://www.vmware.com/vcloud/v1.5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ')
    content_type = "application/vnd.vmware.admin.edgeGatewayServiceConfiguration+xml"
    link = filter(lambda link: link.get_type() == content_type, gateway.me.get_Link())
    headers = vcd_client._get_vcdHeaders()
    content_type = "application/vnd.vmware.admin.edgeGatewayServiceConfiguration+xml"
    headers["Content-Type"] = content_type
    response = requests.post(link[0].get_href(), data=body, headers=headers)
    if response.status_code == requests.codes.accepted:
        task = taskType.parseString(response.content, True)
        return (True, task)
    else:
        return (False, response.content)


def add_pool(pool, network, dhcp_settings):
    ip = _split_adresses(dhcp_settings['dhcp_range'])
    default_lease = DEFAULT_LEASE
    max_lease = MAX_LEASE
    if 'default_lease' in dhcp_settings:
        default_lease = dhcp_settings['default_lease']
    if 'max_lease' in dhcp_settings:
        max_lease = dhcp_settings['max_lease']

    new_pool = DhcpPoolServiceType(IsEnabled=True, Network=network, DefaultLeaseTime=default_lease,
                                   MaxLeaseTime=max_lease,
                                   LowIpAddress=check_ip(ip.start),
                                   HighIpAddress=check_ip(ip.end))
    pool.append(new_pool)
    return pool


def delete_pool(pool, network, dhcp_settings):
    return [p for p in pool if p.get_Network().name != network.name]


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


def _split_adresses(address_range):
    adresses = [ip.strip() for ip in address_range.split('-')]
    IPRange = collections.namedtuple('IPRange', 'start end')
    try:
        start = IP(adresses[0])
        end = IP(adresses[1])
        if start > end:
            raise cfy_exc.NonRecoverableError(
                "Start address {0} is greater than end address: {1}".format(start, end))
        return IPRange(start=start,  end=end)
    except IndexError:
        raise cfy_exc.NonRecoverableError("Can't parse IP range:{0}".
                                          format(address_range))
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addresses: {0}".format(address_range))
