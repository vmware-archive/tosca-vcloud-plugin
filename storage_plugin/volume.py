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
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (wait_for_task, with_vca_client,
                                  get_vcloud_config, get_mandatory,
                                  error_response)
from network_plugin import get_vapp_name


@operation
@with_vca_client
def create_volume(vca_client, **kwargs):
    """
        create new volume, e.g.:
        {
            'use_external_resource': False,
            'volume': {
                'name': 'some-other',
                'size': 11
            }
        }
    """
    if ctx.node.properties.get('use_external_resource'):
        ctx.logger.info("External resource has been used")
        return
    vdc_name = get_vcloud_config()['vdc']
    name = ctx.node.properties['volume']['name']
    size = ctx.node.properties['volume']['size']
    size_in_Mb = size * 1024 * 1024
    ctx.logger.info("Create volume '{0}' to '{1}' with size {2}Mb."
                    .format(name, vdc_name, size_in_Mb))
    success, disk = vca_client.add_disk(vdc_name, name, size_in_Mb)
    if success:
        wait_for_task(vca_client, disk.get_Tasks()[0])
        ctx.logger.info("Volume node '{0}' has been created".format(name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Disk creation error: {0}".format(disk))


@operation
@with_vca_client
def delete_volume(vca_client, **kwargs):
    """
        drop volume
    """
    if ctx.node.properties.get('use_external_resource'):
        ctx.logger.info("External resource has been used")
        return
    vdc_name = get_vcloud_config()['vdc']
    name = ctx.node.properties['volume']['name']
    ctx.logger.info("Delete volume '{0}' from '{1}'."
                    .format(name, vdc_name))
    success, task = vca_client.delete_disk(vdc_name, name)
    if success:
        wait_for_task(vca_client, task)
        ctx.logger.info("Volume node '{0}' has been deleted".format(name))
    else:
        raise cfy_exc.NonRecoverableError(
            "Disk deletion error: {0}".format(task))


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    """
        check volume description
    """
    vdc_name = get_vcloud_config()['vdc']
    disks_names = [
        disk.name for [disk, _vms] in vca_client.get_disks(vdc_name)
    ]
    if ctx.node.properties.get('use_external_resource'):
        resource_id = get_mandatory(ctx.node.properties, 'resource_id')
        if resource_id not in disks_names:
            raise cfy_exc.NonRecoverableError(
                "Disk {} does't exists".format(resource_id))
    else:
        volume = get_mandatory(ctx.node.properties, 'volume')
        name = get_mandatory(volume, 'name')
        if name in disks_names:
            raise cfy_exc.NonRecoverableError(
                "Disk {} already exists".format(name))
        get_mandatory(volume, 'size')


@operation
@with_vca_client
def attach_volume(vca_client, **kwargs):
    """
        attach volume
    """
    _wait_for_boot()
    _volume_operation(vca_client, "ATTACH")


@operation
@with_vca_client
def detach_volume(vca_client, **kwargs):
    """
        detach volume
    """
    _volume_operation(vca_client, "DETACH")


def _volume_operation(vca_client, operation):
    """
        attach/detach volume
    """
    vdc_name = get_vcloud_config()['vdc']
    vdc = vca_client.get_vdc(vdc_name)
    vmName = get_vapp_name(ctx.target.instance.runtime_properties)
    if ctx.source.node.properties.get('use_external_resource'):
        volumeName = ctx.source.node.properties['resource_id']
    else:
        volumeName = ctx.source.node.properties['volume']['name']
    vapp = vca_client.get_vapp(vdc, vmName)
    for ref in vca_client.get_diskRefs(vdc):
        if ref.name == volumeName:
            if operation == 'ATTACH':
                ctx.logger.info("Attach volume node '{0}'.".format(volumeName))
                task = vapp.attach_disk_to_vm(vmName, ref)
                if task:
                    wait_for_task(vca_client, task)
                    ctx.logger.info(
                        "Volume node '{0}' has been attached".format(volumeName))
                else:
                    raise cfy_exc.NonRecoverableError(
                        "Can't attach disk: '{0}' with error: {1}".
                        format(volumeName, error_response(vapp)))

            elif operation == 'DETACH':
                ctx.logger.info("Detach volume node '{0}'.".format(volumeName))
                task = vapp.detach_disk_from_vm(vmName, ref)
                if task:
                    wait_for_task(vca_client, task)
                    ctx.logger.info(
                        "Volume node '{0}' has been detached.".
                        format(volumeName))
                else:
                    raise cfy_exc.NonRecoverableError(
                        "Can't detach disk: '{0}'. With error: {1}".
                        format(volumeName, error_response(vapp)))
            else:
                raise cfy_exc.NonRecoverableError(
                    "Unknown operation '{0}'".format(operation))


def _wait_for_boot():
    from fabric import api as fabric_api
    ip = ctx.target.instance.runtime_properties.get('ssh_public_ip')
    if not ip:
        ip = ctx.target.instance.runtime_properties['ip']
    ctx.logger.info("Usig ip '{0}'.".format(ip))
    for i in range(30):
        ctx.logger.info("Wait for boot '{0}'.".format(i))
        try:
            with fabric_api.settings(host_string=ip, warn_only=True,
                                     abort_on_prompts=True):
                fabric_api.run('ls')
        except SystemExit:
            return
        except Exception:
            pass
    raise cfy_exc.NonRecoverableError("Can't wait for boot")
