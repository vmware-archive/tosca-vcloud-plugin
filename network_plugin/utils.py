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
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.


from cloudify import exceptions as cfy_exc


# 2 ^ 16 - 1
MAX_PORT_NUMBER = 65535
VALID_PROTOCOLS = ["Tcp", "Udp", "Tcpudp", "Icmp", "Any"]


def check_protocol(protocol):
    """
    check protocol
    """
    if protocol is None:
        protocol = 'any'
    if not _protocol_is_valid(protocol):
        raise cfy_exc.NonRecoverableError(
            "Unknown protocol: {0}. Valid protocols are: {1}"
            .format(protocol, VALID_PROTOCOLS))
    return protocol


def _protocol_is_valid(protocol):
    """
    check protocol in list valid protocols
    """
    return protocol.capitalize() in VALID_PROTOCOLS


def check_port(port):
    """
    check port, 1..65535 or 'any'
    """
    if port is None:
        port = 'any'
    if isinstance(port, int):
        if 0 < port < MAX_PORT_NUMBER + 1:
            return port
        else:
            raise cfy_exc.NonRecoverableError(
                "Invalid 'port' value. "
                "Port value must be between 1 and 65535")
    elif isinstance(port, basestring):
        port = port.lower()
        if _port_is_any(port):
            return port
    raise cfy_exc.NonRecoverableError(
        "Parameter 'port' must be integer, or 'any'")


def _port_is_any(port):
    """
    checks that port is 'any'
    """
    return port == 'any'
