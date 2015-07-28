from cloudify import ctx
from cloudify import exceptions as cfy_exc
from cloudify.decorators import operation
import os.path
from os import chmod
from Crypto.PublicKey import RSA
from Crypto import Random

AUTO_GENERATE = 'auto_generate'
PRIVATE_KEY = 'private_key'
PUBLIC_KEY = 'public_key'
PATH = 'path'
KEY = 'key'
USER = 'user'


@operation
def creation_validation(**kwargs):
    """
        check availability of path used in field private_key_path of
        node properties
    """
    key_path = ctx.node.properties.get(PRIVATE_KEY, {}).get(PATH)
    if key_path:
        key_path = os.path.expanduser(key_path)
        if not os.path.isfile(key_path):
            raise cfy_exc.NonRecoverableError(
                "Private key file {0} is absent".format(key_path))


@operation
def create(**kwargs):
    ctx.instance.runtime_properties[PUBLIC_KEY] = {}
    ctx.instance.runtime_properties[PRIVATE_KEY] = {}
    ctx.instance.runtime_properties[PUBLIC_KEY][USER] = \
        ctx.node.properties.get(PUBLIC_KEY, {}).get(USER)
    if ctx.node.properties.get(AUTO_GENERATE):
        ctx.logger.info("Generating ssh keypair")
        public, private = _generate_pair()
        ctx.instance.runtime_properties[PRIVATE_KEY][PATH] = _create_path()
        ctx.instance.runtime_properties[PRIVATE_KEY][KEY] = private
        ctx.instance.runtime_properties[PUBLIC_KEY][KEY] = public
        _save_key_file(ctx.instance.runtime_properties[PRIVATE_KEY][PATH],
                       ctx.instance.runtime_properties[PRIVATE_KEY][KEY])
    else:
        ctx.instance.runtime_properties[PUBLIC_KEY][KEY] = \
            ctx.node.properties.get(PUBLIC_KEY, {}).get(KEY)
        ctx.instance.runtime_properties[PRIVATE_KEY][KEY] = \
            ctx.node.properties.get(PRIVATE_KEY, {}).get(KEY)
        ctx.instance.runtime_properties[PRIVATE_KEY][PATH] = \
            ctx.node.properties.get(PRIVATE_KEY, {}).get(PATH)
        if ctx.node.properties.get(PRIVATE_KEY, {}).get(KEY):
            ctx.instance.runtime_properties[PRIVATE_KEY][PATH] = _create_path()
            _save_key_file(ctx.instance.runtime_properties[PRIVATE_KEY][PATH],
                           ctx.instance.runtime_properties[PRIVATE_KEY][KEY])


@operation
def delete(**kwargs):
    if ctx.node.properties[AUTO_GENERATE]:
        _delete_key_file(ctx.instance.runtime_properties[PRIVATE_KEY][PATH])
    else:
        if ctx.node.properties.get(PRIVATE_KEY, {}).get(KEY):
            _delete_key_file(ctx.instance.runtime_properties[PRIVATE_KEY][PATH])
    del ctx.instance.runtime_properties[PRIVATE_KEY]
    del ctx.instance.runtime_properties[PUBLIC_KEY]


def _generate_pair():
    Random.atfork()  # uses for strong key generation
    key = RSA.generate(2048)
    private_value = key.exportKey('PEM')
    public_value = key.publickey().exportKey('OpenSSH')
    return public_value, private_value


def _create_path():
    if ctx._local:
        key_dir = ctx._context['storage']._storage_dir
    else:
        key_dir = os.path.dirname(os.environ['VIRTUALENV'])
    return '{}/{}_private.key'.format(key_dir, ctx.instance.id)


def _save_key_file(path, value):
    path = os.path.expanduser(path)
    with open(path, 'w') as content_file:
        chmod(path, 0600)
        content_file.write(value)


def _delete_key_file(path):
    os.unlink(os.path.expanduser(path))
