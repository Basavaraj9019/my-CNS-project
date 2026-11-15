"""
Receiver Application Server (Laptop 2).
Exposes network endpoints for receiving encrypted emails, verifies signatures,
enforces replay protection, decrypts AES-256-GCM payloads, and serves the Receiver Web UI.
"""

import os
import sys
import argparse
import json
from flask import Flask, request, jsonify, render_template

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared import (
    SecureMessageEnvelope,
    get_primary_local_ip,
    get_all_local_ips,
    b64encode_str,
    b64decode_bytes
)
from database import ReceiverDatabase
from receiver.receiver_crypto import ReceiverCryptoService


def create_receiver_app(
    db_path: str = None,
    keys_dir: str = None,
    receiver_id: str = "bob@laptop2.sec",
    key_size: int = 2048
) -> Flask:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if db_path is None:
        db_path = os.path.join(base_dir, "receiver.db")
    if keys_dir is None:
        keys_dir = os.path.join(base_dir, "keys")

    template_dir = os.path.join(base_dir, "receiver_ui", "templates")
    static_dir = os.path.join(base_dir, "receiver_ui", "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )

    db = ReceiverDatabase(db_path)
    crypto_service = ReceiverCryptoService(
        keys_dir=keys_dir,
        receiver_id=receiver_id,
        key_size=key_size
    )

    # Store profile in database
    db.set_profile(receiver_id, crypto_service.fingerprint, key_size)

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            receiver_id=receiver_id,
            fingerprint=crypto_service.fingerprint,
            local_ips=get_all_local_ips()
        )

    @app.route("/api/status", methods=["GET"])
    def get_status():
        return jsonify({
            "status": "online",
            "role": "receiver",
            "receiver_id": receiver_id,
            "fingerprint": crypto_service.fingerprint,
            "key_size": crypto_service.key_size,
            "primary_ip": get_primary_local_ip(),
            "all_ips": get_all_local_ips()
        })

    @app.route("/api/identity", methods=["GET"])
    def get_identity():
        """Public endpoint allowing senders to retrieve Receiver's verified public key."""
        return jsonify(crypto_service.get_public_identity())

    @app.route("/api/messages/receive", methods=["POST"])
    def receive_message():
        """
        Receives encrypted message envelope from Sender (Laptop 1) over network.
        Validates envelope format, executes cryptographic verification,
        stores in database, and returns execution status.
        """
        try:
            data = request.get_json(force=True)
            if not data:
                return jsonify({"success": False, "error": "Missing JSON payload"}), 400

            envelope = SecureMessageEnvelope.from_dict(data)

            # Check replay protection
            is_replayed = db.is_message_replayed(envelope.message_id)

            # Check trusted sender record
            trusted_sender = db.get_trusted_sender(envelope.sender_id)

            # Process verification and decryption
            audit_result = crypto_service.process_incoming_envelope(
                envelope=envelope,
                is_replayed=is_replayed,
                trusted_sender_record=trusted_sender
            )

            # Record in replay cache if not already replayed and timestamp is fresh
            if not is_replayed and audit_result["verification_status"] != "TIMESTAMP_EXPIRED":
                db.register_replay_cache(envelope.message_id, envelope.sender_id, envelope.timestamp)

            # Record message in inbox database
            db.record_inbox_message(
                message_id=envelope.message_id,
                sender_id=envelope.sender_id,
                receiver_id=envelope.receiver_id,
                subject=envelope.subject,
                timestamp=envelope.timestamp,
                raw_envelope_json=envelope.to_json(),
                decrypted_body=audit_result["decrypted_body"],
                sha256_hash=audit_result["sha256_hash"],
                verification_status=audit_result["verification_status"],
                integrity_status=audit_result["integrity_status"],
                signature_status=audit_result["signature_status"],
                non_repudiation_status=audit_result["non_repudiation_status"],
                sender_trusted_status=audit_result["sender_trusted_status"],
                error_message=audit_result["error_message"]
            )

            http_status = 200 if audit_result["success"] else 400
            return jsonify({
                "received": True,
                "verification_status": audit_result["verification_status"],
                "message_id": envelope.message_id,
                "audit": audit_result
            }), http_status

        except Exception as e:
            return jsonify({
                "received": False,
                "error": f"Failed to parse or process envelope: {str(e)}"
            }), 400

    @app.route("/api/inbox", methods=["GET"])
    def get_inbox():
        messages = db.list_inbox(limit=100)
        return jsonify({"count": len(messages), "messages": messages})

    @app.route("/api/inbox/<message_id>", methods=["GET"])
    def get_inbox_detail(message_id):
        msg = db.get_inbox_message(message_id)
        if not msg:
            return jsonify({"error": "Message not found"}), 404

        # Parse raw envelope for cryptographic display
        envelope_data = {}
        try:
            envelope_data = json.loads(msg["raw_envelope_json"])
        except Exception:
            pass

        return jsonify({
            "message": msg,
            "envelope": envelope_data
        })

    @app.route("/api/trusted_senders", methods=["GET", "POST"])
    def handle_trusted_senders():
        if request.method == "POST":
            data = request.get_json(force=True)
            sender_id = data.get("sender_id")
            pub_pem = data.get("public_key_pem")
            fingerprint = data.get("fingerprint")
            is_verified = int(data.get("is_verified", 1))

            if not sender_id or not pub_pem or not fingerprint:
                return jsonify({"error": "sender_id, public_key_pem, and fingerprint required"}), 400

            db.upsert_trusted_sender(sender_id, pub_pem, fingerprint, is_verified)
            return jsonify({"success": True, "sender_id": sender_id})

        senders = db.list_trusted_senders()
        return jsonify({"senders": senders})

    @app.route("/api/tamper_simulation", methods=["POST"])
    def run_tamper_simulation():
        """
        Interactive endpoint demonstrating security defenses against specific attack types:
        1. 'tamper_ciphertext': Flips 1 bit in ciphertext -> fails AES-GCM tag.
        2. 'tamper_signature': Corrupts digital signature -> fails RSA-PSS verification.
        3. 'tamper_subject': Alters header in transit -> fails AAD tag verification.
        4. 'replay_attack': Attempts to resend previously processed message -> caught by replay cache.
        """
        data = request.get_json(force=True)
        message_id = data.get("message_id")
        attack_type = data.get("attack_type", "tamper_ciphertext")

        record = db.get_inbox_message(message_id)
        if not record:
            return jsonify({"error": "Original message not found for simulation"}), 404

        envelope_dict = json.loads(record["raw_envelope_json"])
        envelope = SecureMessageEnvelope.from_dict(envelope_dict)

        if attack_type == "tamper_ciphertext":
            # Flip first byte of ciphertext
            ct = envelope.ciphertext
            tampered_ct = bytes([ct[0] ^ 0x01]) + ct[1:]
            envelope.ciphertext = tampered_ct

        elif attack_type == "tamper_signature":
            # Corrupt signature bytes
            sig = envelope.digital_signature
            tampered_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
            envelope.digital_signature = tampered_sig

        elif attack_type == "tamper_subject":
            envelope.subject = envelope.subject + " [MALICIOUSLY INJECTED]"

        elif attack_type == "replay_attack":
            # Message is deliberately re-tested as already seen in cache
            pass

        # Evaluate against crypto service
        is_replayed = (attack_type == "replay_attack") or db.is_message_replayed(envelope.message_id)
        trusted_sender = db.get_trusted_sender(envelope.sender_id)

        sim_result = crypto_service.process_incoming_envelope(
            envelope=envelope,
            is_replayed=is_replayed,
            trusted_sender_record=trusted_sender
        )

        return jsonify({
            "simulation_attack": attack_type,
            "defense_triggered": not sim_result["success"],
            "verification_status": sim_result["verification_status"],
            "error_message": sim_result["error_message"],
            "audit_log": sim_result["audit_log"]
        })

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Laptop 2: Secure Email Receiver Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0 for LAN)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--identity", default="bob@laptop2.sec", help="Receiver email/identity identifier")
    parser.add_argument("--key-size", type=int, default=2048, choices=[2048, 3072], help="RSA key bit length")
    args = parser.parse_args()

    app = create_receiver_app(receiver_id=args.identity, key_size=args.key_size)
    primary_ip = get_primary_local_ip()
    all_ips = get_all_local_ips()

    print("\n" + "=" * 70)
    print("      SECURE EMAIL COMMUNICATION SYSTEM - RECEIVER (LAPTOP 2)      ")
    print("=" * 70)
    print(f"  * Identity:         {args.identity}")
    print(f"  * Binding Host:     {args.host}")
    print(f"  * Port:             {args.port}")
    print(f"  * Primary LAN IP:   {primary_ip}")
    print(f"  * Available IPs:    {', '.join(all_ips)}")
    print(f"  * Receiver URL:     http://{primary_ip}:{args.port}/")
    print("=" * 70)
    print("  [FIREWALL INSTRUCTION FOR WINDOWS LAPTOP 2]")
    print(f"  Open PowerShell as Administrator and run:")
    print(f'  New-NetFirewallRule -DisplayName "SecureEmail Receiver" -Direction Inbound -LocalPort {args.port} -Protocol TCP -Action Allow')
    print("=" * 70 + "\n")

    app.run(host=args.host, port=args.port, debug=False)
