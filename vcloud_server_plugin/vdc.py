
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

from vcloud_plugin_common import (get_vcloud_config,
                                  wait_for_task,
                                  with_vca_client,
                                  is_subscription,
                                  error_response)

VDC_NAME = 'vdc_name'
RESOURCE_ID = 'resource_id'
USE_EXTERNAL_RESOURCE = 'use_external_resource'


@operation(resumable=True)
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """check params

        e.g.:
            {
                'name': 'not_existed'
            }
        or:
            {
                'use_external_resource': True,
                'resource_id': 'not_existed'
            }

    """
    if ctx.node.properties.get(USE_EXTERNAL_RESOURCE):
        if not ctx.node.properties.get(RESOURCE_ID):
            raise cfy_exc.NonRecoverableError(
                "resource_id server properties must be specified")
        res_id = ctx.node.properties[RESOURCE_ID]
        vdc = vca_client.get_vdc(res_id)
        if not vdc:
            raise cfy_exc.NonRecoverableError(
                "Unable to find external VDC {0}."
                .format(res_id))
    else:
        vdc_name = ctx.node.properties.get('name')
        if not vdc_name:
            raise cfy_exc.NonRecoverableError("'vdc_name' not specified.")
        vdc = vca_client.get_vdc(vdc_name)
        if vdc:
            raise cfy_exc.NonRecoverableError(
                "VDC '{0}' already exists."
                .format(vdc_name))


@operation(resumable=True)
@with_vca_client
def create(vca_client, **kwargs):
    """create vdc"""
    config = get_vcloud_config()
    # Subscription service does not support vdc create,
    # you must use predefined vdc only
    if is_subscription(config['service_type']):
        raise cfy_exc.NonRecoverableError(
            "Unable create VDC on subscription service.")
    if ctx.node.properties.get(USE_EXTERNAL_RESOURCE):
        # use external resource, does not create anything
        res_id = ctx.node.properties[RESOURCE_ID]
        ctx.instance.runtime_properties[VDC_NAME] = res_id
        vdc = vca_client.get_vdc(res_id)
        if not vdc:
            raise cfy_exc.NonRecoverableError(
                "Unable to find external VDC {0}."
                .format(res_id))
        ctx.logger.info(
            "External resource {0} has been used".format(res_id))
    else:
        # create new vdc
        vdc_name = ctx.node.properties.get('name')
        if not vdc_name:
            raise cfy_exc.NonRecoverableError("'vdc_name' not specified.")
        task = vca_client.create_vdc(vdc_name)
        if not task:
            raise cfy_exc.NonRecoverableError(
                "Could not create VDC: {0}".format(error_response(vca_client)))
        wait_for_task(vca_client, task)


@operation(resumable=True)
@with_vca_client
def delete(vca_client, **kwargs):
    """delete vdc"""
    # external resource - no actions
    if ctx.node.properties.get(USE_EXTERNAL_RESOURCE):
        ctx.logger.info('Not deleting VDC since an external VDC is '
                        'being used')
    else:
        # created in our workflow
        vdc_name = ctx.node.properties.get('name')
        status, task = vca_client.delete_vdc(vdc_name)
        if not status:
            raise cfy_exc.NonRecoverableError(
                "Could not delete VDC: {0}".format(error_response(vca_client)))
        wait_for_task(vca_client, task)
    # clean up runtime_properties
    if VDC_NAME in ctx.instance.runtime_properties:
        del ctx.instance.runtime_properties[VDC_NAME]
