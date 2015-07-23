from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
import os.path
from os import chmod
from Crypto.PublicKey import RSA

PRIVATE_KEY_PATH = 'private_key_path'
PRIVATE_KEY_VALUE = 'private_key_value'
PUBLIC_KEY_VALUE = 'public_key_value'
AUTO_GENERATE = 'auto_generate'


@operation
def creation_validation(**kwargs):
    """
        check availability of path used in field private_key_path of
        node properties
    """
    key = ctx.node.properties.get(PRIVATE_KEY_PATH)
    if key:
        key_path = os.path.expanduser(key)
        if not os.path.isfile(key_path):
            raise cfy_exc.NonRecoverableError(
                "Private key file {0} is absent".format(key_path))


@operation
def create(**kwargs):
    if ctx.node.properties.get(AUTO_GENERATE):
        ctx.logger.info("Generating ssh keypair")
        public, private = 'public', 'private'
        #_generate_pair()
        ctx.instance.runtime_properties[PRIVATE_KEY_PATH] = _create_path()
        ctx.instance.runtime_properties[PRIVATE_KEY_VALUE] = private
        ctx.instance.runtime_properties[PUBLIC_KEY_VALUE] = public
        _save_key_file(ctx.instance.runtime_properties[PRIVATE_KEY_PATH],
                       ctx.instance.runtime_properties[PRIVATE_KEY_VALUE])
    else:
        if ctx.node.properties[PRIVATE_KEY_VALUE]:
            ctx.instance.runtime_properties[PRIVATE_KEY_PATH] = _create_path()
            _save_key_file(ctx.instance.runtime_properties[PRIVATE_KEY_PATH],
                           ctx.node.properties[PRIVATE_KEY_VALUE])


@operation
def delete(**kwargs):
    if ctx.node.properties[AUTO_GENERATE]:
        _delete_key_file(ctx.instance.runtime_properties[PRIVATE_KEY_PATH])
        del ctx.instance.runtime_properties[PRIVATE_KEY_PATH]
        del ctx.instance.runtime_properties[PRIVATE_KEY_VALUE]
        del ctx.instance.runtime_properties[PUBLIC_KEY_VALUE]
    else:
        if ctx.node.properties[PRIVATE_KEY_VALUE]:
            _delete_key_file(ctx.instance.runtime_properties[PRIVATE_KEY_PATH])
            del ctx.instance.runtime_properties[PRIVATE_KEY_PATH]


def _generate_pair():
    key = RSA.generate(2048)
    private_value = key.exportKey('PEM')
    public_value = key.publickey().exportKey('OpenSSH')
    return public_value, private_value


def _create_path():
    return '~/.ssh/{}_private.key'.format(ctx.instance.id)


def _save_key_file(path, value):
    path = os.path.expanduser(path)
    with open(path, 'w') as content_file:
        chmod(path, 0600)
        content_file.write(value)


def _delete_key_file(path):
    os.unlink(os.path.expanduser(path))
