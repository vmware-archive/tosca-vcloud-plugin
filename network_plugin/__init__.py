from IPy import IP
from cloudify import exceptions as cfy_exc


def check_ip(address):
    try:
        IP(address)
    except ValueError:
        raise cfy_exc.NonRecoverableError(
            "Incorrect Ip addres: {0}".format(address))
    return address
