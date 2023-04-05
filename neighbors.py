import configparser
import logging
import math
import os
import socket
import sys
import time
from dataclasses import dataclass
from typing import Optional

import scapy.config
import scapy.layers.l2
import scapy.route
from scapy.utils import ltoa

import measurements_api

logging.basicConfig(level=logging.INFO, format="[%(asctime)-15s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Device:
    mac: str
    ip: str
    hostname: Optional[str] = None
    
    def __hash__(self):
        return hash(self.mac)


def long2net(arg):
    if arg <= 0 or arg >= 0xFFFFFFFF:
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_cidr_notation(bytes_network, bytes_netmask) -> Optional[str]:
    network = ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        return None

    return net


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def find_neighbor_devices_in_net_from_interface(
    net, interface, timeout=5
) -> set[Device]:
    logger.info("arping %s on %s" % (net, interface))
    res = set()
    ans, unans = scapy.layers.l2.arping(
        net, iface=interface, timeout=timeout, verbose=False
    )
    for _, r in ans.res:
        mac = r.src
        ip = r.psrc
        hostname = resolve_hostname(ip)
        res.add(
            Device(
                mac=mac,
                ip=ip,
                hostname=hostname,
            )
        )
    return res


def assert_root():
    if os.geteuid() != 0:
        logger.warning("You need to be root to run this script")
        sys.exit(1)


def is_relevant_route(network, netmask, interface, address):
    if (
        network == 0
        or interface == "lo"
        or address == "127.0.0.1"
        or address == "0.0.0.0"
    ):
        return False

    if netmask <= 0 or netmask == 0xFFFFFFFF:
        return False

    if (
        interface.startswith("docker")
        or interface.startswith("br-")
        or interface.startswith("tun")
    ):
        return False

    return True


def load_blacklist() -> set[str]:
    with open("blacklist") as f:
        return set([line.strip() for line in f])


def load_whitelist() -> list[set[str]]:
    res = []
    with open("whitelist") as f:
        for row in f:
            res.append(set(row.strip().split(" ")))
    return res


def filter_unique_new_devices(
    devices: set[Device], whitelist: list[set], blacklist: set[str]
) -> set[Device]:
    result: set = set()
    seen: set = set()
    for device in devices:
        if device.mac in blacklist:
            continue
        if device.mac in seen:
            logger.info(f"{device.mac} belongs to a whitelisted group")
            continue

        logger.info(f"{device.mac} is counted")
        result.add(device)

        for group in whitelist:
            if device.mac in group:
                seen = seen.union(group)

    return result


def find_unique_devices_in_network() -> set[Device]:
    whitelist = load_whitelist()
    blacklist = load_blacklist()

    devices: set = set()
    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:

        if not is_relevant_route(network, netmask, interface, address):
            continue

        if not (net := to_cidr_notation(network, netmask)):
            continue

        devices = devices.union(find_neighbor_devices_in_net_from_interface(net, interface))

    unique_devices = filter_unique_new_devices(devices, whitelist, blacklist)
    return unique_devices


config = configparser.ConfigParser()
config.read("config.ini")


def send_unique_devices_count(count: int):
    api = measurements_api.MeasurementsAPI(
        url=config["INFLUXDB"]["URL"],
        token=config["INFLUXDB"]["TOKEN"],
    )
    m = measurements_api.Measurement(measurement_name="occupancy", value=count, tags={})
    api.send_measurement(m)


def main():
    retry_count = int(config["MAIN"]["RETRY_COUNT"])
    retry_interval = int(config['MAIN']['RETRY_INTERVAL'])
    main_interval = int(config["MAIN"]["INTERVAL"])
    
    while True:
        unique_devices_in_network = set()
        
        for i in range(retry_count):
            
            logger.info(f'Scanning attempt {i} of {retry_interval}')
            
            unique_devices_in_network = unique_devices_in_network.union(
                find_unique_devices_in_network()
            )
            
            time.sleep(retry_interval)

        send_unique_devices_count(count=len(unique_devices_in_network))
        time.sleep(main_interval)


if __name__ == "__main__":
    assert_root()
    main()
