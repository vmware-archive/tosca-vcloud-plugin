from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import (wait_for_task, with_vca_client, get_vcloud_config, get_mandatory)
from network_plugin import get_vapp_name


@operation
@with_vca_client
def create_volume(vca_client, **kwargs):
    if ctx.node.properties['use_external_resource']:
        ctx.logger.info("External resource has been used")
        return
    vdc_name = get_vcloud_config()['vdc']
    name = ctx.node.properties['volume']['name']
    size = ctx.node.properties['volume']['size']
    size_in_Mb = size * 1024 * 1024
    success, disk = vca_client.add_disk(vdc_name, name, size_in_Mb)
    if success:
        wait_for_task(vca_client, disk.get_Tasks()[0])
        ctx.logger.info("Volume node {} has been created".format(name))
    else:
        raise cfy_exc.NonRecoverableError("Disk creation error: {0}".format(disk))


@operation
@with_vca_client
def delete_volume(vca_client, **kwargs):
    if ctx.node.properties['use_external_resource']:
        ctx.logger.info("External resource has been used")
        return
    vdc_name = get_vcloud_config()['vdc']
    name = ctx.node.properties['volume']['name']
    success, task = vca_client.delete_disk(vdc_name, name)
    if success:
        wait_for_task(vca_client, task)
        ctx.logger.info("Volume node {} has been deleted".format(name))
    else:
        raise cfy_exc.NonRecoverableError("Disk deletion error: {0}".format(task))


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    vdc_name = get_vcloud_config()['vdc']
    disks_names = [d[0].name for d in vca_client.get_disks(vdc_name)]
    if ctx.node.properties['use_external_resource']:
        resource_id = get_mandatory(ctx.node.properties, 'resource_id')
        if resource_id not in disks_names:
            raise cfy_exc.NonRecoverableError("Disk {} does't exists".format(resource_id))
    else:
        volume = get_mandatory(ctx.node.properties, 'volume')
        name = get_mandatory(volume, 'name')
        if name in disks_names:
            raise cfy_exc.NonRecoverableError("Disk {} already exists".format(name))
        get_mandatory(volume, 'size')


@operation
@with_vca_client
def attach_volume(vca_client, **kwargs):
    _volume_operation(vca_client, "ATTACH")


@operation
@with_vca_client
def detach_volume(vca_client, **kwargs):
    _volume_operation(vca_client, "DETACH")


def _volume_operation(vca_client, operation):
    vdc_name = get_vcloud_config()['vdc']
    vdc = vca_client.get_vdc(vdc_name)
    volumeName = ctx.target.node.properties['volume']['name']
    if ctx.target.node.properties['use_external_resource']:
        vmName = ctx.target.node.properties['resource_id']
    else:
        vmName = get_vapp_name(ctx.source.instance.runtime_properties)
    vapp = vca_client.get_vapp(vdc, vmName)
    for ref in vca_client.get_diskRefs(vdc):
        if ref.name == volumeName:
            if operation == 'ATTACH':
                task = vapp.attach_disk_to_vm(vmName, ref)
                if task:
                    wait_for_task(vca_client, task)
                    ctx.logger.info("Volume node {} has been attached".format(volumeName))
                else:
                    raise cfy_exc.NonRecoverableError("Can't attach disk: {0}".format(volumeName))

            elif operation == 'DETACH':
                task = vapp.detach_disk_from_vm(vmName, ref)
                if task:
                    wait_for_task(vca_client, task)
                    ctx.logger.info("Volume node {} has been detached".format(volumeName))
                else:
                    raise cfy_exc.NonRecoverableError("Can't attach disk: {0}".format(volumeName))
            else:
                raise cfy_exc.NonRecoverableError("Unknown operation {0}".format(operation))
