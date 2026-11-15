#!/usr/bin/env python3
"""
Launcher script for Laptop 2 (Receiver Application).
Listens on 0.0.0.0 for incoming encrypted messages from Laptop 1.
"""

import sys
import os
import argparse

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from receiver.receiver_app import create_receiver_app
from shared import get_primary_local_ip, get_all_local_ips


def main():
    parser = argparse.ArgumentParser(
        description="Laptop 2: Secure Email Communication System - Receiver",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host interface to bind. Use 0.0.0.0 to listen on all network interfaces (LAN/Wi-Fi)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000)."
    )
    parser.add_argument(
        "--identity",
        default="bob@laptop2.sec",
        help="Receiver identity / email address (default: bob@laptop2.sec)."
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        choices=[2048, 3072],
        help="RSA key bit size: 2048 or 3072 (default: 2048)."
    )

    args = parser.parse_args()

    # Paths
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, "receiver", "receiver.db")
    keys_dir = os.path.join(base_dir, "receiver", "keys")

    app = create_receiver_app(
        db_path=db_path,
        keys_dir=keys_dir,
        receiver_id=args.identity,
        key_size=args.key_size
    )

    primary_ip = get_primary_local_ip()
    all_ips = get_all_local_ips()

    print("\n" + "=" * 76)
    print("      SECURE EMAIL COMMUNICATION SYSTEM - RECEIVER STATION (LAPTOP 2)      ")
    print("=" * 76)
    print(f"  * Receiver Identity:   {args.identity}")
    print(f"  * Cryptography Suite:  AES-256-GCM + RSA-{args.key_size} (OAEP/PSS) + SHA-256")
    print(f"  * Bound Host:          {args.host} (All Network Interfaces)")
    print(f"  * Port:                {args.port}")
    print(f"  * Primary LAN IPv4:    {primary_ip}")
    print(f"  * All Detected IPs:    {', '.join(all_ips)}")
    print("-" * 76)
    print(f"  --> RECEIVER WEB UI:   http://localhost:{args.port}/  (or http://{primary_ip}:{args.port}/)")
    print("=" * 76)
    print("  [WINDOWS DEFENDER FIREWALL CONFIGURATION FOR LAPTOP 2]")
    print(f"  To allow Laptop 1 to connect, open PowerShell as Administrator and run:")
    print(f'  New-NetFirewallRule -DisplayName "SecureEmail Receiver" -Direction Inbound -LocalPort {args.port} -Protocol TCP -Action Allow')
    print("=" * 76 + "\n")

    try:
        app.run(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n[!] Receiver service stopped by user.")


if __name__ == "__main__":
    main()
