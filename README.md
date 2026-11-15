# Secure Email Communication System Using Hybrid Cryptography and Digital Signatures

A production-grade, dual-device secure email communication system that resolves the fundamental vulnerabilities of traditional SMTP email (cleartext transmission, eavesdropping, message tampering, sender impersonation, and lack of non-repudiation).

Built with **AES-256-GCM**, **RSA-OAEP (2048/3072-bit)**, **RSA-PSS Digital Signatures**, **SHA-256 Hashing**, **Associated Authenticated Data (AAD)**, and **Replay Protection**, operating across **two physically separate Windows laptops over a local area network (LAN / Wi-Fi)**.

---

## 1. System Architecture

```
+--------------------------------------------------------------------------------------------------+
|                                    LAPTOP 1: SENDER (e.g., 192.168.1.10)                         |
|                                                                                                  |
|   +------------------------------------------------------------------------------------------+   |
|   | SENDER APPLICATION (Flask UI + API: 0.0.0.0:5001)                                        |   |
|   | - Sender RSA-2048/3072 Key Pair (Private key kept strictly in sender/keys/sender_priv.pem)|  |
|   | - Address Book: Trusted Receiver Public Keys & SHA-256 Fingerprints                      |   |
|   +------------------------------------------------------------------------------------------+   |
|                                             |                                                    |
|                                             v                                                    |
|   [1. SHA-256 Hash] ------> [2. RSA-PSS Sign] ------> Digital Signature                         |
|   [3. Message Body] ------> [4. AES-256-GCM]  ------> Ciphertext + Nonce (96-bit) + Auth Tag     |
|   [5. Random 256-bit AES Key] -> [6. RSA-OAEP] -----> Encrypted Session Key                      |
|                                             |                                                    |
|                                             v                                                    |
|                    Assemble Standard Secure Wire Payload (JSON)                                  |
+--------------------------------------------------------------------------------------------------+
                                              |
                                              | Local Wi-Fi / Ethernet Network (LAN)
                                              | HTTP POST to http://<Laptop2-IP>:5000/api/messages/receive
                                              v
+--------------------------------------------------------------------------------------------------+
|                                   LAPTOP 2: RECEIVER (e.g., 192.168.1.20)                        |
|                                                                                                  |
|   +------------------------------------------------------------------------------------------+   |
|   | RECEIVER APPLICATION (Flask UI + API: 0.0.0.0:5000)                                      |   |
|   | - Receiver RSA-2048/3072 Key Pair (Private kept strictly in receiver/keys/rec_priv.pem)  |   |
|   | - Address Book: Trusted Sender Public Keys & SHA-256 Fingerprints                        |   |
|   | - Replay Protection Cache Table & Timestamp Freshness Window (300s TTL)                  |   |
|   +------------------------------------------------------------------------------------------+   |
|                                             |                                                    |
|                                             v                                                    |
|   [1. Replay Check] ------> Verifies UUIDv4 message_id & Timestamp (Rejects duplicates/replay)   |
|   [2. Decrypt AES Key] ---> RSA-OAEP with Receiver Private Key -> Recovers Session Key           |
|   [3. Decrypt & Verify] --> AES-256-GCM with Session Key, Nonce & Tag -> Recovers Plaintext      |
|                             * If Tag check fails -> INTEGRITY COMPROMISED (Content blocked)      |
|   [4. Verify Hash] -------> Computes SHA-256 of decrypted body, compares with wire hash          |
|   [5. Verify Signature] --> RSA-PSS with Sender Public Key                                       |
|                             * If Signature invalid -> AUTHENTICATION FAILED (Content blocked)    |
|   [6. Identity Trust] ----> Verifies sender fingerprint against registered trusted directory     |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Algorithms and Security Roles

| Cryptographic Primitive | Algorithm Specification | Security Purpose & Defense Mechanism |
| :--- | :--- | :--- |
| **Symmetric Payload Encryption** | **AES-256-GCM** (Galois/Counter Mode) | Provides **Confidentiality** and **Ciphertext Integrity**. Uses a fresh 256-bit session key and a 96-bit random IV (nonce) for every message. Generates a 128-bit authentication tag. |
| **Associated Authenticated Data (AAD)** | Deterministic header binding (`v1\|msg_id\|sender\|receiver\|timestamp\|subject`) | Binds email metadata to the ciphertext so that in-transit tampering with the subject, sender, or timestamp causes the AEAD tag check to fail immediately. |
| **Session Key Encapsulation** | **RSA-OAEP** (2048 or 3072-bit) with **SHA-256** and **MGF1** | Provides **Secure Key Exchange**. Ensures only the holder of the receiver's private key can decrypt the 256-bit AES session key. OAEP eliminates plaintext padding oracle attacks. |
| **Digital Signature Generation** | **RSA-PSS** with **SHA-256** and maximal salt length | Provides **Authentication** and **Non-Repudiation**. Proves that the message was signed by the sender's private key and cannot be denied later. |
| **Message Integrity Digest** | **SHA-256** | Generates an immutable 256-bit cryptographic fingerprint of the original plaintext body. |
| **Public Key Fingerprinting** | **SHA-256(DER(Public Key))** formatted as `SHA256:xx:xx:...` | Prevents **Man-in-the-Middle (MITM) & Public-Key Substitution** attacks by allowing out-of-band verification of identities. |
| **Random Number Generation** | **OS CSPRNG** (`os.urandom`) | Generates cryptographically secure session keys, nonces, and initialization vectors. |
| **Replay Attack Defense** | SQLite Unique `message_id` Cache + 300-second timestamp sliding window | Prevents adversaries from capturing and replaying previous legitimate transmissions. |

> **Critical Security Rule:** Private keys are generated locally and stored exclusively in private local folders (`sender/keys/` and `receiver/keys/`). Private keys are **NEVER** transmitted over the network or exposed via API.

---

## 3. Project Directory Structure

```
secure_email/
├── run_receiver.py                 # Laptop 2 entry point (Binds to 0.0.0.0:5000)
├── run_sender.py                   # Laptop 1 entry point (Binds to 0.0.0.0:5001)
├── requirements.txt                # Python dependencies
├── README.md                       # Complete documentation & dual-laptop guide
│
├── crypto/                         # Standalone cryptographic engine
│   ├── __init__.py
│   ├── key_management.py           # RSA key generation, PEM export/load, fingerprints
│   ├── encryption.py               # AES-256-GCM, RSA-OAEP, SHA-256 hashing
│   ├── decryption.py               # Authenticated decryption, tag verification
│   └── digital_signature.py        # RSA-PSS signing & verification
│
├── sender/                         # Laptop 1 (Sender) Application
│   ├── sender_app.py               # Flask application server & API routes
│   ├── sender_crypto.py            # Packaging, signing, hybrid encryption pipeline
│   ├── sender.db                   # SQLite outbox & trusted receiver keys
│   ├── keys/                       # Local private & public RSA keys
│   └── sender_ui/
│       ├── templates/index.html    # Cybersecurity-themed dark dashboard
│       └── static/
│           ├── css/styles.css      # Dark navy/cyan styling
│           └── js/sender.js        # Network client, telemetry, UI logic
│
├── receiver/                       # Laptop 2 (Receiver) Application
│   ├── receiver_app.py             # Flask application server & API routes
│   ├── receiver_crypto.py          # Decryption, AEAD tag check, signature audit
│   ├── receiver.db                 # SQLite inbox & replay cache
│   ├── keys/                       # Local private & public RSA keys
│   └── receiver_ui/
│       ├── templates/index.html    # Cybersecurity-themed dark dashboard
│       └── static/
│           ├── css/styles.css      # Dark navy/emerald styling
│           └── js/receiver.js      # Polling, 4-pillar audit, tamper lab
│
├── shared/                         # Shared wire protocol & networking
│   ├── __init__.py
│   ├── protocol.py                 # JSON envelope, Base64 encoding, AAD
│   └── network_utils.py            # Local IPv4 auto-detection
│
├── certificates/                   # TLS / HTTPS transport support
│   └── generate_cert.py            # Self-signed X.509 certificate generator
│
└── tests/                          # Automated security test suites
    ├── test_crypto.py              # Cryptographic primitive unit tests
    ├── test_tampering.py           # Attack detection (bit-flips, forged signatures)
    ├── test_replay.py              # Replay protection & timestamp expiry tests
    ├── test_network_e2e.py         # End-to-end integration tests
    └── test_live_sockets.py        # Real parallel TCP socket tests
```

---

## 4. Dual-Device Execution Instructions (Two Physical Windows Laptops)

Follow these steps to run the system across two separate Windows laptops on the same Wi-Fi or LAN.

### Prerequisite: Connect Both Laptops to the Same Network
Ensure Laptop 1 and Laptop 2 are connected to the same Wi-Fi router, mobile hotspot, or Ethernet switch so they can communicate over local IPv4 addresses.

---

### Step 1: Set Up Laptop 2 (Receiver)

1. Open **Command Prompt** or **PowerShell** on Laptop 2 and navigate to the project directory:
   ```cmd
   cd secure_email
   ```
2. Install Python dependencies:
   ```cmd
   python -m pip install -r requirements.txt
   ```
3. Allow incoming traffic on port 5000 through the Windows Defender Firewall.
   Open **PowerShell as Administrator** and execute:
   ```powershell
   New-NetFirewallRule -DisplayName "SecureEmail Receiver" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
   ```
4. Start the Receiver Application:
   ```cmd
   python run_receiver.py
   ```
   * The console will display:
     ```
     ============================================================================
           SECURE EMAIL COMMUNICATION SYSTEM - RECEIVER STATION (LAPTOP 2)
     ============================================================================
       * Receiver Identity:   bob@laptop2.sec
       * Cryptography Suite:  AES-256-GCM + RSA-2048 (OAEP/PSS) + SHA-256
       * Bound Host:          0.0.0.0 (All Network Interfaces)
       * Port:                5000
       * Primary LAN IPv4:    192.168.1.20
     ----------------------------------------------------------------------------
       --> RECEIVER WEB UI:   http://localhost:5000/
     ============================================================================
     ```
5. Note Laptop 2's **Primary LAN IPv4** (e.g., `192.168.1.20`).
6. Open your web browser on Laptop 2 and navigate to:
   ```
   http://localhost:5000/
   ```

---

### Step 2: Set Up Laptop 1 (Sender)

1. Open **Command Prompt** or **PowerShell** on Laptop 1 and navigate to the project directory:
   ```cmd
   cd secure_email
   ```
2. Install Python dependencies:
   ```cmd
   python -m pip install -r requirements.txt
   ```
3. Start the Sender Application:
   ```cmd
   python run_sender.py
   ```
4. Open your web browser on Laptop 1 and navigate to:
   ```
   http://localhost:5001/
   ```
5. On the Sender Web Dashboard:
   - In the **Laptop 2 Network Target** box:
     - Enter Laptop 2's IPv4 address (e.g., `192.168.1.20`).
     - Enter Port `5000`.
     - Click **"Test Connection & Retrieve Receiver Public Key"**.
   - The connection pill turns **GREEN** with the exact round-trip ping latency (e.g., `8.4 ms`), and Laptop 2's verified public key and SHA-256 fingerprint appear.

---

### Step 3: Transmit a Secure Email from Laptop 1 to Laptop 2

1. On Laptop 1's composer:
   - **Recipient:** `bob@laptop2.sec`
   - **Subject:** `Confidential Q4 Financial Audit & Security Keys`
   - **Body:** `The strategic deployment is approved. Symmetric encryption verified.`
   - **Security Testing Mode:** Select `Normal Secure Delivery (No Tampering)`.
   - Click **"Encrypt, Sign & Send Over Network"**.
2. **Cryptographic Telemetry Displayed on Laptop 1:**
   - Real-time SHA-256 digest computation.
   - RSA-PSS digital signature generation with sender's private key.
   - Ephemeral 256-bit AES key generation & 96-bit nonce.
   - AES-256-GCM ciphertext + 128-bit authentication tag generation.
   - RSA-OAEP session key encryption using Laptop 2's public key.
   - HTTP POST transmission over LAN.

---

### Step 4: Verification on Laptop 2

1. Within seconds, Laptop 2's Inbox receives the message and updates in real-time.
2. Click on the message in Laptop 2's inbox.
3. The **Cryptographic Inspector** displays:
   - **Confidentiality:** `[PASSED]` (Decrypted AES session key with Receiver private key).
   - **Message Integrity:** `[PASSED]` (128-bit AES-GCM tag matches; SHA-256 digest confirmed).
   - **Authentication:** `[PASSED]` (RSA-PSS digital signature matches Sender's public key).
   - **Non-Repudiation:** `[PASSED]` (Sender identity confirmed via verified fingerprint).
   - **Original Decrypted Body:** Cleanly displayed with green security verification badge.
   - **Audit Trail:** Step-by-step verification logs with microsecond precision.
   - **Wire Payload Inspector:** Displays the raw encrypted JSON showing zero plaintext on the wire.

---

## 5. Security Testing & Tamper Attack Demonstration

The system includes a dedicated **Security Testing Laboratory** in both the Sender and Receiver interfaces to demonstrate the 8 mandatory security test cases:

### Test 1: Normal Secure Communication
- **Execution:** Send message with `Normal Secure Delivery`.
- **Expected Result:** Delivered, decrypted, all 4 security pillars marked **PASSED**.

### Test 2: Wire Payload Confidentiality (No Plaintext)
- **Execution:** Inspect the sent message in the Outbox or click *"View Raw Transmitted Envelope"*.
- **Expected Result:** Only Base64-encoded ciphertext, encrypted session key, nonce, and signature are transmitted. Plaintext never touches the network wire.

### Test 3: Integrity Compromise Detection (Modified Ciphertext)
- **Execution:** In the Sender Tamper Mode, select `[ATTACK 1] Tamper Ciphertext (Flip bit)` and send, or click *"Test: Tamper Ciphertext"* on Receiver.
- **Expected Result:** AES-256-GCM authentication tag check fails (`cryptography.exceptions.InvalidTag`). Receiver immediately flags `INTEGRITY_COMPROMISED`, blocks the message, and withholds the plaintext body with an alert.

### Test 4: Sender Impersonation / Forged Signature Detection
- **Execution:** Select `[ATTACK 2] Corrupt Digital Signature` and send, or click *"Test: Corrupt Signature"* on Receiver.
- **Expected Result:** RSA-PSS signature verification fails. Receiver flags `INVALID_SIGNATURE`, marks Non-Repudiation as `FAILED`, and displays a cryptographic forgery warning.

### Test 5: In-Transit Header Modification Detection
- **Execution:** Select `[ATTACK 3] Tamper Subject / Header` and send.
- **Expected Result:** The message headers are bound into AES-GCM **Associated Authenticated Data (AAD)**. Altering the subject causes the GCM tag verification to fail, blocking in-transit tampering of metadata.

### Test 6: Public Key Substitution / Rogue Sender Detection
- **Execution:** Select `[ATTACK 4] Rogue Key Substitution` and send.
- **Expected Result:** Attacker replaces the public key with their own. Receiver checks the SHA-256 fingerprint against the trusted address book, flags `UNTRUSTED_KEY_SUBSTITUTION`, and blocks the communication.

### Test 7: Unauthorized Recipient Decryption Failure
- **Execution:** Covered in unit test `test_unauthorized_rsa_decryption_failure`. If an attacker intercepts the encrypted session key, attempting to decrypt it with any RSA private key other than Laptop 2's yields an OAEP padding error and blocks decryption.

### Test 8: Replay Attack Defense
- **Execution:** Click *"Test: Replay Attack"* on Receiver, or re-send a duplicate payload with the same `message_id`.
- **Expected Result:** The Receiver queries its SQLite `replay_cache`. The duplicate is flagged as `REPLAY_DETECTED` and immediately rejected.

---

## 6. Running the Automated Test Suite

Run the complete test suite covering all cryptographic primitives, tamper attacks, replay protection, and parallel TCP sockets:

```cmd
python -m unittest discover -s tests -v
```

### Test Suite Summary:
- `tests/test_crypto.py`: Validates RSA keypair generation, AES-256-GCM, RSA-OAEP, RSA-PSS signatures, and tag integrity.
- `tests/test_tampering.py`: Validates interception and rejection of bit flips, signature corruption, and key substitution.
- `tests/test_replay.py`: Validates replay cache barriers and timestamp freshness drift windows.
- `tests/test_network_e2e.py`: Validates API endpoints, serialization, and database state transitions.
- `tests/test_live_sockets.py`: Launches Sender and Receiver on parallel threads listening on live TCP sockets and executes network transmissions.

---

## 7. Transport Layer Security (Optional HTTPS / TLS)

To add transport layer security (Defense-in-Depth):
1. Generate self-signed certificates:
   ```cmd
   python certificates/generate_cert.py
   ```
2. Certificates (`cert.pem` and `key.pem`) are generated in `certificates/`.
3. Pass `ssl_context=('certificates/cert.pem', 'certificates/key.pem')` in `app.run()`.

---

## 8. Troubleshooting Network Connectivity

If Laptop 1 displays `Connection timed out` or `Cannot reach Laptop 2`:
1. **Verify Same Network:** Ensure both laptops are on the same Wi-Fi network (or mobile hotspot with client isolation disabled).
2. **Ping Test:** On Laptop 1, run `ping <Laptop2-IP>`.
3. **Windows Defender Firewall:** On Laptop 2, ensure inbound TCP port 5000 is allowed:
   ```powershell
   New-NetFirewallRule -DisplayName "SecureEmail Receiver" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
   ```
4. **Port In Use:** If port 5000 is occupied by another service on Laptop 2, launch Receiver on port 5500:
   ```cmd
   python run_receiver.py --port 5500
   ```
   Then enter port 5500 on Laptop 1's Sender interface.
