import ipaddress
import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil


PORT = 5055
TIMEOUT = 0.6
MAX_WORKERS = 64
MAX_HOSTS_PER_NETWORK = 256


def get_local_networks():
    """Find active private IPv4 networks."""
    networks = set()

    addresses = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()

    for interface_name, interface_addresses in addresses.items():
        stats = interface_stats.get(interface_name)

        if not stats or not stats.isup:
            continue

        for address in interface_addresses:
            if address.family != socket.AF_INET:
                continue

            ip = address.address
            netmask = address.netmask

            if not ip or not netmask:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip)

                if (
                    ip_obj.is_loopback
                    or ip_obj.is_link_local
                    or not ip_obj.is_private
                ):
                    continue

                interface = ipaddress.IPv4Interface(
                    f"{ip}/{netmask}"
                )
                network = interface.network

                # Avoid unexpectedly large network scans.
                if network.num_addresses > MAX_HOSTS_PER_NETWORK:
                    network = ipaddress.ip_network(
                        f"{ip}/24",
                        strict=False
                    )

                networks.add(network)

            except ValueError:
                continue

    return networks


def check_netbridge_device(ip):
    """Verify that an IP is hosting NetBridge."""
    url = f"http://{ip}:{PORT}/health"

    try:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json"}
        )

        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT
        ) as response:

            if response.status != 200:
                return None

            data = json.loads(
                response.read().decode("utf-8")
            )

            if (
                data.get("service") != "NetBridge Network Service"
                or data.get("status") != "running"
            ):
                return None

            return {
                "ip": ip,
                "port": PORT,
                "service": data["service"],
                "status": "online"
            }

    except (
        OSError,
        ValueError,
        json.JSONDecodeError
    ):
        return None


def discover_netbridge_devices():
    """Discover NetBridge services on local private IPv4 networks."""
    targets = set()

    for network in get_local_networks():
        targets.update(
            str(ip)
            for ip in network.hosts()
        )

    devices = []

    if not targets:
        return devices

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(check_netbridge_device, ip)
            for ip in targets
        ]

        for future in as_completed(futures):
            try:
                device = future.result()

                if device:
                    devices.append(device)

            except Exception:
                continue

    return sorted(
        devices,
        key=lambda device: tuple(
            int(part) for part in device["ip"].split(".")
        )
    )