# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from cloudify import ctx
from cloudify.decorators import operation

from vcloud_plugin_common import transform_resource_name, with_vcloud_client

@operation
@with_vcloud_client
def create(vcloud_client, **kwargs):
    ctx.instance.runtime_properties['floating_ip'] = ctx.node.properties['floatingip']

    
@operation
@with_vcloud_client
def delete(vcloud_client, **kwargs):
    del ctx.instance.runtime_properties['floating_ip']

    
@operation
@with_vcloud_client
def connect_floatingip(vcloud_client, **kwargs):
    if 'floating_ip' in  ctx.source.instance.runtime_properties:
        translated_ip = ctx.source.instance.runtime_properties['floating_ip']
    else:
        raise cfy_exc.NonRecoverableError("Could not get float ip address")
    
    vappName = ctx.node.properties['server']['name']
    vapp = cloud_client.get_vApp(vappName)
    if not vapp:
        raise cfy_exc.NonRecoverableError("Could not find vApp")
    vm_info = filter(lambda details: details[0] == vappName, vapp.details_of_vms())[0]
    original_ip = vm_info[7]
    gateway  = vcloud_client.get_gateways(ctx.node.properties['gateway'])
    if gateway:
            gateway.add_nat_rule("SNAT", original_ip, "ANY",
                                 translated_ip, "ANY", "ANY")
            gateway.add_nat_rule("DNAT", translated_ip, "ANY",
                                 original_ip, "ANY", "ANY")

            
@operation
@with_vcloud_client
def disconnect_floatingip(vcloud_client, **kwargs):
    pass
