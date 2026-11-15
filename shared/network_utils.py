"""
Network utility helpers for discovering local IPv4 addresses and interface bindings.
Assists users when deploying across two physical Windows laptops.
"""

import socket
from typing import List, Tuple


def get_primary_local_ip() -> str:
    """
    Attempts to identify the host machine's primary LAN IPv4 address (e.g. 192.168.x.x or 10.x.x.x).
    Uses a standard non-transmitting socket routing query.
    Falls back to hostname resolution if offline.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually establish connection or send packets; kernel queries routing table
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_all_local_ips() -> List[str]:
    """
    Returns all non-loopback IPv4 addresses bound to local network adapters.
    """
    ips = set()
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    primary = get_primary_local_ip()
    if primary and not primary.startswith("127."):
        ips.add(primary)

    result = list(ips)
    if not result:
        result.append("127.0.0.1")
    return sorted(result)
