from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
import os.path


@operation
def creation_validation(**kwargs):
    key = ctx.node.properties.get('private_key_path')
    if key:
        key_path = os.path.expanduser(key)
        if not os.path.isfile(key_path):
            raise cfy_exc.NonRecoverableError(
                "Private key file {0} is absent".format(key_path))
