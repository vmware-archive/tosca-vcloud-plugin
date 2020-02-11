# Copyright (c) 2015-2020 Cloudify Platform Ltd. All rights reserved
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
from setuptools import setup

setup(
    zip_safe=True,
    name='tosca-vcloud-plugin',
    version='1.6.1',
    packages=[
        'vcloud_plugin_common',
        'vcloud_server_plugin',
        'vcloud_storage_plugin',
        'vcloud_network_plugin'
    ],
    license='LICENSE',
    description='Cloudify plugin for vmWare vCloud infrastructure.',
    install_requires=[
        'cloudify-common>=4.5.0',
        'pyvcloud==18.2.2',
        'IPy==1.00',
        'pycrypto==2.6.1',
        # used in volume creation
        'paramiko>=1.18.3',
        'fabric>=1.13.1,<2.0', # 2+ branch has API changes
    ]
)
