"""
Sender Application Server (Laptop 1).
Exposes sender interface, manages identity keys, handles receiver discovery,
assembles hybrid encrypted & digitally signed envelopes, and transmits them across LAN/WAN.
"""

import os
import sys
import argparse
import time
import json
import requests
from flask import Flask, request, jsonify, render_template

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared import (
    SecureMessageEnvelope,
    get_primary_local_ip,
    get_all_local_ips
)
from database import SenderDatabase
from sender.sender_crypto import SenderCryptoService


def create_sender_app(
    db_path: str = None,
    keys_dir: str = None,
    sender_id: str = "alice@laptop1.sec",
    key_size: int = 2048
) -> Flask:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if db_path is None:
        db_path = os.path.join(base_dir, "sender.db")
    if keys_dir is None:
        keys_dir = os.path.join(base_dir, "keys")

    template_dir = os.path.join(base_dir, "sender_ui", "templates")
    static_dir = os.path.join(base_dir, "sender_ui", "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )

    db = SenderDatabase(db_path)
    crypto_service = SenderCryptoService(
        keys_dir=keys_dir,
        sender_id=sender_id,
        key_size=key_size
    )

    # Store profile in database
    db.set_profile(sender_id, crypto_service.fingerprint, key_size)

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            sender_id=sender_id,
            fingerprint=crypto_service.fingerprint,
            local_ips=get_all_local_ips()
        )

    @app.route("/api/status", methods=["GET"])
    def get_status():
        return jsonify({
            "status": "online",
            "role": "sender",
            "sender_id": sender_id,
            "fingerprint": crypto_service.fingerprint,
            "key_size": crypto_service.key_size,
            "primary_ip": get_primary_local_ip(),
            "all_ips": get_all_local_ips()
        })

    @app.route("/api/identity", methods=["GET"])
    def get_identity():
        return jsonify(crypto_service.get_public_identity())

    @app.route("/api/receiver/test_connection", methods=["POST"])
    def test_receiver_connection():
        """
        Pings remote Receiver on Laptop 2 via HTTP over LAN to test reachability,
        measure round-trip latency, and download Receiver's public identity.
        """
        data = request.get_json(force=True)
        host_ip = data.get("host_ip", "").strip()
        port = int(data.get("port", 5000))

        if not host_ip:
            return jsonify({"success": False, "error": "Receiver IP address is required"}), 400

        target_url = f"http://{host_ip}:{port}/api/identity"
        start_time = time.time()
        try:
            resp = requests.get(target_url, timeout=4.0)
            latency_ms = round((time.time() - start_time) * 1000, 2)

            if resp.status_code == 200:
                receiver_data = resp.json()
                # Save or update receiver in local address book
                db.upsert_receiver(
                    receiver_id=receiver_data["receiver_id"],
                    public_key_pem=receiver_data["public_key_pem"],
                    fingerprint=receiver_data["fingerprint"],
                    host_ip=host_ip,
                    port=port,
                    is_verified=1
                )
                return jsonify({
                    "success": True,
                    "latency_ms": latency_ms,
                    "target_url": target_url,
                    "receiver_info": receiver_data
                })
            else:
                return jsonify({
                    "success": False,
                    "error": f"Receiver returned HTTP {resp.status_code}: {resp.text}"
                }), 400

        except requests.exceptions.ConnectTimeout:
            return jsonify({
                "success": False,
                "error": f"Connection timed out connecting to {host_ip}:{port}. Check Windows Firewall or IP."
            }), 504
        except requests.exceptions.ConnectionError as e:
            return jsonify({
                "success": False,
                "error": f"Cannot reach Laptop 2 at {host_ip}:{port}. Verify Receiver application is running and both laptops are on the same Wi-Fi/LAN."
            }), 502
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/receivers", methods=["GET", "POST"])
    def handle_receivers():
        if request.method == "POST":
            data = request.get_json(force=True)
            db.upsert_receiver(
                receiver_id=data["receiver_id"],
                public_key_pem=data["public_key_pem"],
                fingerprint=data["fingerprint"],
                host_ip=data.get("host_ip", ""),
                port=int(data.get("port", 5000)),
                is_verified=int(data.get("is_verified", 1))
            )
            return jsonify({"success": True})

        receivers = db.list_receivers()
        return jsonify({"receivers": receivers})

    @app.route("/api/messages/send", methods=["POST"])
    def send_secure_message():
        """
        Encrypts, signs, and transmits email to Receiver on Laptop 2 over LAN.
        Supports security testing modes (e.g. tamper_ciphertext, tamper_signature).
        """
        data = request.get_json(force=True)
        receiver_id = data.get("receiver_id", "").strip()
        host_ip = data.get("host_ip", "").strip()
        port = int(data.get("port", 5000))
        subject = data.get("subject", "").strip()
        body = data.get("body", "")
        tamper_mode = data.get("tamper_mode", None)

        if not receiver_id:
            return jsonify({"success": False, "error": "Receiver identity is required"}), 400
        if not host_ip:
            return jsonify({"success": False, "error": "Receiver IP address is required"}), 400
        if not subject:
            return jsonify({"success": False, "error": "Message subject is required"}), 400

        # Retrieve receiver's public key from database or query live
        receiver_record = db.get_receiver(receiver_id)
        receiver_pub_pem = None

        if receiver_record and receiver_record.get("public_key_pem"):
            receiver_pub_pem = receiver_record["public_key_pem"]
        else:
            # Query live from receiver
            try:
                resp = requests.get(f"http://{host_ip}:{port}/api/identity", timeout=3.0)
                if resp.status_code == 200:
                    rec_info = resp.json()
                    receiver_pub_pem = rec_info["public_key_pem"]
                    db.upsert_receiver(
                        receiver_id=rec_info["receiver_id"],
                        public_key_pem=rec_info["public_key_pem"],
                        fingerprint=rec_info["fingerprint"],
                        host_ip=host_ip,
                        port=port
                    )
            except Exception as e:
                return jsonify({
                    "success": False,
                    "error": f"Failed to retrieve receiver's public key from {host_ip}:{port}: {str(e)}"
                }), 502

        if not receiver_pub_pem:
            return jsonify({"success": False, "error": f"Could not obtain public key for {receiver_id}"}), 400

        # Create cryptographic envelope and telemetry
        try:
            envelope, telemetry = crypto_service.prepare_secure_envelope(
                receiver_id=receiver_id,
                receiver_public_key_pem=receiver_pub_pem,
                subject=subject,
                message_body=body,
                tamper_mode=tamper_mode
            )
        except Exception as e:
            return jsonify({"success": False, "error": f"Cryptographic packaging failed: {str(e)}"}), 500

        # Transmit to Laptop 2 Receiver Endpoint
        target_endpoint = f"http://{host_ip}:{port}/api/messages/receive"
        envelope_dict = envelope.to_dict()
        network_status = "PENDING"
        receiver_response_data = None
        http_code = 0

        try:
            post_resp = requests.post(
                target_endpoint,
                json=envelope_dict,
                headers={"Content-Type": "application/json"},
                timeout=6.0
            )
            http_code = post_resp.status_code
            try:
                receiver_response_data = post_resp.json()
            except Exception:
                receiver_response_data = {"raw_text": post_resp.text}

            if post_resp.status_code == 200:
                network_status = "DELIVERED_AND_AUTHENTICATED"
            else:
                network_status = f"REJECTED_BY_RECEIVER (HTTP {post_resp.status_code})"

        except requests.exceptions.ConnectTimeout:
            network_status = "FAILED_TIMEOUT"
            receiver_response_data = {"error": f"Connection timed out reaching {target_endpoint}"}
        except requests.exceptions.ConnectionError:
            network_status = "FAILED_UNREACHABLE"
            receiver_response_data = {"error": f"Could not reach {target_endpoint}. Receiver offline or blocked by firewall."}
        except Exception as e:
            network_status = "FAILED_EXCEPTION"
            receiver_response_data = {"error": str(e)}

        # Record in local outbox
        db.record_outbox_message(
            message_id=envelope.message_id,
            receiver_id=receiver_id,
            subject=subject,
            sha256_hash=envelope.sha256_hash_hex,
            status=network_status,
            payload_json=envelope.to_json(),
            plaintext_body=body
        )

        return jsonify({
            "success": (network_status == "DELIVERED_AND_AUTHENTICATED"),
            "network_status": network_status,
            "http_code": http_code,
            "message_id": envelope.message_id,
            "telemetry": telemetry,
            "envelope_preview": {
                "message_id": envelope.message_id,
                "timestamp": envelope.timestamp,
                "ciphertext_snippet": envelope_dict["ciphertext"][:48] + "...",
                "session_key_snippet": envelope_dict["encrypted_session_key"][:48] + "...",
                "signature_snippet": envelope_dict["digital_signature"][:48] + "...",
                "auth_tag": envelope_dict["auth_tag"],
                "nonce": envelope_dict["nonce"],
                "sha256_hash": envelope.sha256_hash_hex
            },
            "receiver_response": receiver_response_data
        })

    @app.route("/api/outbox", methods=["GET"])
    def get_outbox():
        messages = db.list_outbox(limit=100)
        return jsonify({"count": len(messages), "messages": messages})

    @app.route("/api/outbox/<message_id>", methods=["GET"])
    def get_outbox_detail(message_id):
        msg = db.get_outbox_message(message_id)
        if not msg:
            return jsonify({"error": "Message not found"}), 404
        return jsonify({"message": msg})

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Laptop 1: Secure Email Sender Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5001, help="Port to listen on (default: 5001)")
    parser.add_argument("--identity", default="alice@laptop1.sec", help="Sender email/identity identifier")
    parser.add_argument("--key-size", type=int, default=2048, choices=[2048, 3072], help="RSA key bit length")
    args = parser.parse_args()

    app = create_sender_app(sender_id=args.identity, key_size=args.key_size)
    primary_ip = get_primary_local_ip()
    all_ips = get_all_local_ips()

    print("\n" + "=" * 70)
    print("       SECURE EMAIL COMMUNICATION SYSTEM - SENDER (LAPTOP 1)       ")
    print("=" * 70)
    print(f"  * Identity:         {args.identity}")
    print(f"  * Binding Host:     {args.host}")
    print(f"  * Port:             {args.port}")
    print(f"  * Primary LAN IP:   {primary_ip}")
    print(f"  * Available IPs:    {', '.join(all_ips)}")
    print(f"  * Sender Dashboard: http://localhost:{args.port}/ (or http://{primary_ip}:{args.port}/)")
    print("=" * 70 + "\n")

    app.run(host=args.host, port=args.port, debug=False)
