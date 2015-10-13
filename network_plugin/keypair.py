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
CREATE_PRIVATE_KEY_FILE = 'create_file'
CLOUDIFY_AGENT = 'cloudify_agent'
PATH = 'path'
KEY = 'key'
USER = 'user'
HOME = 'home'
SSH_KEY = 'ssh_key'


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
    ctx.instance.runtime_properties[PUBLIC_KEY][HOME] = \
        ctx.node.properties.get(PUBLIC_KEY, {}).get(HOME)
    if ctx.node.properties.get(AUTO_GENERATE):
        ctx.logger.info("Generating ssh keypair")
        public, private = _generate_pair()
        ctx.instance.runtime_properties[PRIVATE_KEY][KEY] = private
        ctx.instance.runtime_properties[PUBLIC_KEY][KEY] = public
        if ctx.node.properties.get(PRIVATE_KEY, {}).get(CREATE_PRIVATE_KEY_FILE):
            ctx.instance.runtime_properties[PRIVATE_KEY][PATH] = _create_path()
            _save_key_file(ctx.instance.runtime_properties[PRIVATE_KEY][PATH],
                           ctx.instance.runtime_properties[PRIVATE_KEY][KEY])
    else:
        ctx.instance.runtime_properties[PUBLIC_KEY][KEY] = \
            ctx.node.properties.get(PUBLIC_KEY, {}).get(KEY)
        ctx.instance.runtime_properties[PRIVATE_KEY][KEY] = \
            ctx.node.properties.get(PRIVATE_KEY, {}).get(KEY)
        ctx.instance.runtime_properties[PRIVATE_KEY][PATH] = \
            ctx.node.properties.get(PRIVATE_KEY, {}).get(PATH)
        if ctx.node.properties.get(PRIVATE_KEY, {}).get(CREATE_PRIVATE_KEY_FILE):
            if ctx.node.properties.get(PRIVATE_KEY, {}).get(KEY):
                ctx.instance.runtime_properties[PRIVATE_KEY][PATH] = _create_path()
                _save_key_file(ctx.instance.runtime_properties[PRIVATE_KEY][PATH],
                               ctx.instance.runtime_properties[PRIVATE_KEY][KEY])


@operation
def delete(**kwargs):
    if ctx.node.properties[AUTO_GENERATE]:
        if ctx.node.properties.get(PRIVATE_KEY, {}).get(CREATE_PRIVATE_KEY_FILE):
            _delete_key_file(ctx.instance.runtime_properties)
    else:
        if ctx.node.properties.get(PRIVATE_KEY, {}).get(KEY):
            if ctx.node.properties.get(PRIVATE_KEY, {}).get(CREATE_PRIVATE_KEY_FILE):
                _delete_key_file(ctx.instance.runtime_properties)
    if PRIVATE_KEY in ctx.instance.runtime_properties:
        del ctx.instance.runtime_properties[PRIVATE_KEY]
    if PUBLIC_KEY in ctx.instance.runtime_properties:
        del ctx.instance.runtime_properties[PUBLIC_KEY]


@operation
def server_connect_to_keypair(**kwargs):
    host_rt_properties = ctx.source.instance.runtime_properties
    target_rt_properties = ctx.target.instance.runtime_properties
    if SSH_KEY not in host_rt_properties:
        host_rt_properties[SSH_KEY] = {}
    if PRIVATE_KEY in target_rt_properties:
        host_rt_properties[SSH_KEY][PATH] = target_rt_properties[PRIVATE_KEY].get(PATH)
        host_rt_properties[SSH_KEY][KEY] = target_rt_properties[PRIVATE_KEY].get(KEY)
    if PUBLIC_KEY in target_rt_properties:
        host_rt_properties[SSH_KEY][USER] = target_rt_properties[PUBLIC_KEY].get(USER)
    if target_rt_properties[PRIVATE_KEY].get(PATH):
        host_rt_properties[CLOUDIFY_AGENT] = {}
        host_rt_properties[CLOUDIFY_AGENT][KEY] = target_rt_properties[PRIVATE_KEY].get(PATH)
    ctx.source.instance.update()


@operation
def server_disconnect_from_keypair(**kwargs):
    host_rt_properties = ctx.source.instance.runtime_properties
    if SSH_KEY in host_rt_properties:
        del host_rt_properties[SSH_KEY]
    if CLOUDIFY_AGENT in host_rt_properties:
        del host_rt_properties[CLOUDIFY_AGENT]


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


def _delete_key_file(properties):
    if PRIVATE_KEY in properties and PATH in properties[PRIVATE_KEY]:
        path = properties[PRIVATE_KEY][PATH]
        os.unlink(os.path.expanduser(path))
