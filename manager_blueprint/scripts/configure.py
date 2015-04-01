import tempfile
import json

import fabric

import vcloud_plugin_common


def configure(vcloud_config):
    _copy_vsphere_configuration_to_manager(vcloud_config)
    _update_vm()


def _copy_vsphere_configuration_to_manager(vcloud_config):
    tmp = tempfile.mktemp()
    with open(tmp, 'w') as f:
        json.dump(vcloud_config, f)
    fabric.api.put(tmp,
                   vcloud_plugin_common.Config.VCLOUD_CONFIG_PATH_DEFAULT)


def _get_distro():
    """ detect current distro """
    return fabric.api.run(
        'python -c "import platform; print platform.dist()[0]"')


def _update_vm():
    """ install some packeges for future deployments creation """
    distro = _get_distro()
    if 'Ubuntu' in distro:
        # update system to last version
        fabric.api.run("sudo apt-get update -q -y 2>&1")
        fabric.api.run("sudo apt-get dist-upgrade -q -y 2>&1")
        # install:
        # * zram-config for minimize out-of-memory cases with zswap
        # * other packages for create deployments from source
        fabric.api.run("sudo apt-get install zram-config gcc python-dev "
                       "libxml2-dev libxslt-dev -q -y 2>&1")
