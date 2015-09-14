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

import fabric


def configure(vcloud_config):
    """
        only update container with vcloud specific packages
    """
    _update_container()


def _update_container():
    """ install some packeges for future deployments creation """
    # update system to last version
    fabric.api.run("sudo docker exec -i -t cfy apt-get "
                   "update -q -y 2>&1")
    fabric.api.run("sudo docker exec -i -t cfy apt-get "
                   "dist-upgrade -q -y 2>&1")
    # install:
    fabric.api.run("sudo docker exec -i -t cfy apt-get "
                   "install gcc python-dev libxml2-dev libxslt-dev "
                   "zlib1g-dev -q -y 2>&1")
