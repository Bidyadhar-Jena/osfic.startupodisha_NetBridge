"""Basic host and Internet status checks for NetBridge.

This module deliberately does not inspect or use Wi-Fi or Bluetooth.
NetBridge communication is based on ordinary local-network HTTP requests.
"""
import platform
import socket


def check_internet(timeout=2):
    """Return whether a public HTTPS endpoint can be reached by TCP."""
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=timeout):
            return True
    except OSError:
        return False


def get_network_status():
    """Return general host/network status without Wi-Fi/Bluetooth checks."""
    internet_available = check_internet()
    return {
        "platform": platform.system(),
        "internet": {
            "available": internet_available,
            "status": "Available" if internet_available else "Unavailable",
        },
        "communication": {
            "method": "local_network_http",
            "status": "Available for local-network testing",
        },
        "communication_readiness": (
            "Local-network HTTP discovery enabled; Internet is not required "
            "for devices on the same reachable network."
        ),
        "mode": "network_monitor_only",
    }
