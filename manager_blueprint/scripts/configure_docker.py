import fabric


def configure(vcloud_config):
    _update_vm()


def _get_distro():
    """ detect current distro """
    return fabric.api.run(
        'python -c "import platform; print platform.dist()[0]"')


def _update_vm():
    """ install some packeges for future deployments creation """
    distro = _get_distro()
    if 'Ubuntu' in distro:
        # update system to last version
        fabric.api.run("sudo docker exec -i -t cfy apt-get "
                       "update -q -y 2>&1")
        fabric.api.run("sudo docker exec -i -t cfy apt-get "
                       "dist-upgrade -q -y 2>&1")
        # install:
        fabric.api.run("sudo docker exec -i -t cfy apt-get "
                       "install gcc python-dev libxml2-dev libxslt-dev "
                       "zlib1g-dev -q -y 2>&1")
