from vcloud_plugin_common import Config, VcloudDirectorClient
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import OrgVdcNetworkType
from pyvcloud.helper import generalHelperFunctions as ghf

content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
vcd_client = VcloudDirectorClient().get()
link = filter(lambda link: link.get_type() == content_type, vdc_client.get_Link())
net = OrgVdcNetworkType()
body = '<?xml version="1.0" encoding="UTF-8"?>' + \
       ghf.convertPythonObjToStr(net, name = 'OrgVdcNetwork',
       namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ')
response = requests.post(link[0].get_href(), data=body, headers=self.headers)
print response.status_code
