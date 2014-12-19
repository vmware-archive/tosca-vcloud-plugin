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

from vcloud_plugin_common import with_vcd_client

VCLOUD_NETWORK_NAME = 'vcloud_network_name'


@operation
@with_vcd_client
def create(vcd_client, **kwargs):
    if ctx.node.properties['use_external_resource'] is True:
        ctx.instance.runtime_properties[VCLOUD_NETWORK_NAME] = \
            ctx.node.properties['resource_id']


@operation
@with_vcd_client
def delete(vcd_client, **kwargs):
    pass
