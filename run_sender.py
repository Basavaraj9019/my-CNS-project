#!/usr/bin/env python3
"""
Launcher script for Laptop 1 (Sender Application).
Provides sender dashboard and sends encrypted messages to Laptop 2.
"""

import sys
import os
import argparse

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from sender.sender_app import create_sender_app
from shared import get_primary_local_ip, get_all_local_ips


def main():
    parser = argparse.ArgumentParser(
        description="Laptop 1: Secure Email Communication System - Sender",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host interface to bind. Use 0.0.0.0 for LAN or 127.0.0.1 for local."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5001,
        help="Port to listen on (default: 5001)."
    )
    parser.add_argument(
        "--identity",
        default="alice@laptop1.sec",
        help="Sender identity / email address (default: alice@laptop1.sec)."
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
    db_path = os.path.join(base_dir, "sender", "sender.db")
    keys_dir = os.path.join(base_dir, "sender", "keys")

    app = create_sender_app(
        db_path=db_path,
        keys_dir=keys_dir,
        sender_id=args.identity,
        key_size=args.key_size
    )

    primary_ip = get_primary_local_ip()
    all_ips = get_all_local_ips()

    print("\n" + "=" * 76)
    print("       SECURE EMAIL COMMUNICATION SYSTEM - SENDER STATION (LAPTOP 1)       ")
    print("=" * 76)
    print(f"  * Sender Identity:     {args.identity}")
    print(f"  * Cryptography Suite:  AES-256-GCM + RSA-{args.key_size} (OAEP/PSS) + SHA-256")
    print(f"  * Bound Host:          {args.host}")
    print(f"  * Port:                {args.port}")
    print(f"  * Primary LAN IPv4:    {primary_ip}")
    print(f"  * All Detected IPs:    {', '.join(all_ips)}")
    print("-" * 76)
    print(f"  --> SENDER WEB UI:     http://localhost:{args.port}/  (or http://{primary_ip}:{args.port}/)")
    print("=" * 76)
    print("  [CONNECTING TO LAPTOP 2]")
    print("  1. Open http://localhost:5001/ in your web browser.")
    print("  2. Enter Laptop 2's IPv4 address and port 5000.")
    print("  3. Click 'Test Connection & Retrieve Receiver Public Key'.")
    print("  4. Compose, Encrypt, Sign, and Send your secure email!")
    print("=" * 76 + "\n")

    try:
        app.run(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n[!] Sender service stopped by user.")


if __name__ == "__main__":
    main()
