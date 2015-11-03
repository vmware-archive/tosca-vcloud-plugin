# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cloudify.decorators import workflow
from cloudify.manager import update_node_instance
import cloudify.plugins.workflows as default_workflow
import vcloud_plugin_common


def update(ctx, instance, token, org_url):
    """update token and url in instance"""
    node_instance = instance._node_instance
    rt_properties = node_instance['runtime_properties']
    rt_properties.update({
        vcloud_plugin_common.SESSION_TOKEN: token,
        vcloud_plugin_common.ORG_URL: org_url
    })
    version = node_instance['version']
    node_instance['version'] = version if version else 0
    if ctx.local:
        version = node_instance['version']
        state = node_instance.get('state')
        node_id = instance.id
        storage = ctx.internal.handler.storage
        storage.update_node_instance(node_id, version, rt_properties, state)
    else:
        update_node_instance(node_instance)


def _get_all_nodes_instances(ctx, token, org_url):
    """return all instances from context nodes"""
    node_instances = set()
    for node in ctx.nodes:
        for instance in node.instances:
            if (vcloud_plugin_common.VCLOUD_CONFIG in node.properties
               and token
               and org_url):
                update(ctx, instance, token, org_url)
            node_instances.add(instance)
    return node_instances


@workflow
def install(ctx, **kwargs):
    """Score install workflow"""

    default_workflow._install_node_instances(
        ctx,
        _get_all_nodes_instances(ctx, kwargs.get('session_token'),
                                 kwargs.get('org_url')),
        set(),
        default_workflow.NodeInstallationTasksSequenceCreator(),
        default_workflow.InstallationTasksGraphFinisher
    )


@workflow
def uninstall(ctx, **kwargs):
    """Score uninstall workflow"""

    default_workflow._uninstall_node_instances(
        ctx,
        _get_all_nodes_instances(ctx, kwargs.get('session_token'),
                                 kwargs.get('org_url')),
        set(),
        default_workflow.NodeUninstallationTasksSequenceCreator(),
        default_workflow.UninstallationTasksGraphFinisher
    )
