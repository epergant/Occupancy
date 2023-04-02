import configparser
import time
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import math
import errno
import os
import getopt
import sys
from dataclasses import dataclass
from typing import Optional
import measurements_api

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@dataclass
class Device:
    mac: str
    ip: str
    hostname: Optional[str] = None


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask) -> str:
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        return None

    return net

def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pass


def find_neighbor_devices_in_net_from_interface(net, interface, timeout=5) -> list[Device]:
    logger.info("arping %s on %s" % (net, interface))
    res = []
    ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
    for _, r in ans.res:
        mac = r.src
        ip = r.psrc
        hostname = resolve_hostname(ip)
        res.append(
            Device(
                mac=mac, ip=ip, hostname=hostname,
            )
        )
        return res

def assert_root():
    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)


def is_relevant_route(network, netmask, interface, address):
    if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
        return False

    if netmask <= 0 or netmask == 0xFFFFFFFF:
        return False

    if interface.startswith('docker') or interface.startswith('br-')  or interface.startswith('tun'):
        return False

    return True


def load_blacklist():
    with open('blacklist') as f:
        return set([l.strip() for l in f])


def load_whitelist():
    return []
    res = set()
    with open('whitelist') as f:
        for row in f:
            res = res.union(set(row.split(',')))


def count_unique_new_devices(devices: list[Device], whitelist: list[set], blacklist: set[str]):
    count = 0
    seen = set()
    for device in devices:
        if device.mac in blacklist:
            print(device.mac + 'blacklisted')
            continue
        for group in whitelist:
            if device.mac in group:
                seen = seen.union(group) 
        count += 1
    return count


def count_unique_devices_in_network() -> int:

    whitelist = load_whitelist()
    blacklist = load_blacklist()

    devices = []
    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:

        if not is_relevant_route(network, netmask, interface, address):
            continue

        if not (net := to_CIDR_notation(network, netmask)):
            continue

        devices += find_neighbor_devices_in_net_from_interface(net, interface)
    
    count = count_unique_new_devices(devices, whitelist, blacklist)
    return count
    
    
config = configparser.ConfigParser()
config.read("config.ini")

def main():
    api = measurements_api.MeasurementsAPI(
        url=config['INFLUXDB']['URL'],
        token=config['INFLUXDB']['TOKEN'],
    )
    while True:
        count = count_unique_devices_in_network()
        m = measurements_api.Measurement(measurement_name='occupancy', value=count, tags={})
        print('Writing measurement')
        api.send_measurement(m)

        time.sleep(int(config['MAIN']['INTERVAL']))


if __name__ == "__main__":

    assert_root()
    main()

