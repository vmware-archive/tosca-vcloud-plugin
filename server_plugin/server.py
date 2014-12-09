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
from cloudify import exceptions as cfy_exc

from vcloud_plugin_common import transform_resource_name, with_vcloud_client

@operation
@with_vcloud_client
def create(vcloud_client, **kwargs):
    server = {
        'name': ctx.instance.id,
    }
    server.update(ctx.node.properties['server'])
    transform_resource_name(server, ctx)
    required_params = ('catalog', 'template')
    missed_params = set(required_params) - set(server.keys())
    if len(missed_params) > 0:
        raise cfy_exc.NonRecoverableError(
            "{0} server properties must be specified"
            .format(list(missed_params)))


@operation
@with_vcloud_client
def start(vcloud_client, **kwargs):
    pass


@operation
@with_vcloud_client
def stop(vcloud_client, **kwargs):
    pass


@operation
@with_vcloud_client
def delete(vcloud_client, **kwargs):
    pass


@operation
@with_vcloud_client
def get_state(vcloud_client, **kwargs):
    pass
