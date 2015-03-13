from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
from vcloud_plugin_common import with_vca_client, get_mandatory
import os.path


@operation
@with_vca_client
def creation_validation(vca_client, **kwargs):
    key = get_mandatory(ctx.node.properties, 'private_key_path')
    if not os.path.isfile(key):
        raise cfy_exc.NonRecoverableError("Private key file {0} is absent".format(key))
