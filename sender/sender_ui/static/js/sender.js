/**
 * Sender Dashboard Client Logic (Laptop 1)
 */

// Override window.alert so that ANY popup dialog box displays "Secure Mail" instead of "Antigravity"
window.alert = function(msg) {
  showSecureMailAlert("Secure Mail", msg);
};

document.addEventListener("DOMContentLoaded", () => {
  loadOutbox();
});

let cachedReceiverData = null;

async function testReceiverConnection() {
  const ip = document.getElementById("target-ip").value.trim();
  const port = document.getElementById("target-port").value.trim();
  const badge = document.getElementById("receiver-conn-badge");
  const detailsBox = document.getElementById("receiver-details-box");

  if (!ip) {
    alert("Please enter Laptop 2's IPv4 address.");
    return;
  }

  badge.className = "badge badge-warning";
  badge.textContent = "Connecting...";

  try {
    const resp = await fetch("/api/receiver/test_connection", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host_ip: ip, port: parseInt(port) })
    });

    const data = await resp.json();

    if (resp.ok && data.success) {
      cachedReceiverData = data.receiver_info;
      badge.className = "badge badge-success";
      badge.textContent = `Connected (${data.latency_ms} ms)`;

      document.getElementById("rec-verified-id").textContent = data.receiver_info.receiver_id;
      document.getElementById("rec-latency").textContent = `${data.latency_ms} ms`;
      document.getElementById("rec-verified-fp").textContent = data.receiver_info.fingerprint;
      detailsBox.style.display = "block";

      // Auto-set receiver ID in form if default
      document.getElementById("msg-receiver-id").value = data.receiver_info.receiver_id;
    } else {
      badge.className = "badge badge-danger";
      badge.textContent = "Connection Failed";
      detailsBox.style.display = "none";
      alert(`Connection to Laptop 2 (${ip}:${port}) failed:\n${data.error || "Receiver unreachable"}`);
    }
  } catch (err) {
    badge.className = "badge badge-danger";
    badge.textContent = "Offline";
    detailsBox.style.display = "none";
    alert(`Network error contacting Laptop 2:\n${err.message}`);
  }
}

async function sendSecureMessage() {
  const host_ip = document.getElementById("target-ip").value.trim();
  const port = parseInt(document.getElementById("target-port").value.trim());
  const receiver_id = document.getElementById("msg-receiver-id").value.trim();
  const subject = document.getElementById("msg-subject").value.trim();
  const body = document.getElementById("msg-body").value;
  const tamperModeVal = document.getElementById("tamper-mode").value;
  const tamper_mode = tamperModeVal === "none" ? null : tamperModeVal;

  const sendBtn = document.getElementById("send-btn");
  sendBtn.disabled = true;
  sendBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing Cryptography & Transmitting...`;

  const telemetryBox = document.getElementById("crypto-telemetry-box");

  try {
    const resp = await fetch("/api/messages/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        receiver_id,
        host_ip,
        port,
        subject,
        body,
        tamper_mode
      })
    });

    const data = await resp.json();

    if (data.telemetry) {
      telemetryBox.style.display = "block";
      document.getElementById("tel-sha256").textContent = data.telemetry.sha256_hash;
      document.getElementById("tel-sig").textContent = `RSA-PSS Signature (${data.telemetry.signature_len} bytes generated)`;
      document.getElementById("tel-aes").textContent = `256-bit Key: ${data.telemetry.session_key_hex.substring(0, 16)}... | 96-bit Nonce: ${data.telemetry.nonce_hex}`;
      document.getElementById("tel-gcm").textContent = `Ciphertext: ${data.telemetry.ciphertext_len} bytes | Auth Tag: ${data.telemetry.auth_tag_hex}`;
      document.getElementById("tel-oaep").textContent = `RSA-OAEP Encrypted Session Key (${data.telemetry.encrypted_session_key_len} bytes)`;
    }

    if (data.success) {
      alert(`SUCCESS!\nMessage delivered and cryptographically authenticated by Laptop 2!\nMessage ID: ${data.message_id}`);
      document.getElementById("msg-subject").value = "";
      document.getElementById("msg-body").value = "";
    } else {
      let reason = data.network_status;
      if (data.receiver_response && data.receiver_response.error) {
        reason += ` - ${data.receiver_response.error}`;
      } else if (data.receiver_response && data.receiver_response.audit && data.receiver_response.audit.error_message) {
        reason += ` - ${data.receiver_response.audit.error_message}`;
      }
      alert(`TRANSMISSION / VERIFICATION RESULT:\n${reason}`);
    }

    loadOutbox();
  } catch (err) {
    alert(`Error transmitting message:\n${err.message}`);
  } finally {
    sendBtn.disabled = false;
    sendBtn.innerHTML = `<i class="fa-solid fa-lock"></i> Encrypt, Sign & Send Over Network`;
  }
}

async function loadOutbox() {
  const tbody = document.getElementById("outbox-tbody");
  try {
    const resp = await fetch("/api/outbox");
    const data = await resp.json();

    if (!data.messages || data.messages.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">
            No messages sent yet. Use the composer above to transmit a secure message to Laptop 2.
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = data.messages.map(m => {
      let badgeClass = "badge-info";
      if (m.status.includes("DELIVERED")) badgeClass = "badge-success";
      else if (m.status.includes("REJECTED") || m.status.includes("FAILED")) badgeClass = "badge-danger";

      return `
        <tr>
          <td><code style="color: var(--accent-cyan); font-size: 0.75rem;">${m.message_id.substring(0, 8)}...</code></td>
          <td><strong>${escapeHtml(m.receiver_id)}</strong></td>
          <td>${escapeHtml(m.subject)}</td>
          <td><code style="font-size: 0.75rem;">${m.sha256_hash.substring(0, 12)}...</code></td>
          <td style="font-size: 0.75rem; color: var(--text-muted);">${formatTimestamp(m.sent_at)}</td>
          <td><span class="badge ${badgeClass}">${m.status}</span></td>
          <td>
            <button class="btn btn-outline btn-sm" onclick="viewOutboxDetail('${m.message_id}')">
              <i class="fa-solid fa-eye"></i> Inspect
            </button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load outbox:", err);
  }
}

async function viewOutboxDetail(msgId) {
  const modal = document.getElementById("outbox-modal");
  const content = document.getElementById("outbox-detail-content");
  modal.classList.add("active");
  content.innerHTML = `<div style="text-align: center; padding: 2rem;">Loading envelope details...</div>`;

  try {
    const resp = await fetch(`/api/outbox/${msgId}`);
    const data = await resp.json();
    const msg = data.message;
    const envelope = JSON.parse(msg.payload_json);

    content.innerHTML = `
      <div class="identity-badge-box">
        <div class="id-field"><span class="id-label">Message ID:</span><span class="id-val">${msg.message_id}</span></div>
        <div class="id-field"><span class="id-label">Sent At:</span><span class="id-val">${msg.sent_at}</span></div>
        <div class="id-field"><span class="id-label">Recipient:</span><span class="id-val">${msg.receiver_id}</span></div>
        <div class="id-field"><span class="id-label">Subject:</span><span class="id-val">${escapeHtml(msg.subject)}</span></div>
        <div class="id-field"><span class="id-label">Network Status:</span><span class="id-val">${msg.status}</span></div>
      </div>

      <div style="margin-top: 1rem;">
        <label class="form-label">Plaintext Message Body (Stored locally on Laptop 1 only):</label>
        <pre class="crypto-dump" style="color: #34d399;">${escapeHtml(msg.plaintext_body || '')}</pre>
      </div>

      <div style="margin-top: 1rem;">
        <label class="form-label">Wire Payload Transmitted Over Network (Notice NO Plaintext):</label>
        <pre class="crypto-dump">${escapeHtml(JSON.stringify(envelope, null, 2))}</pre>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div style="color: var(--accent-red);">Error loading message: ${err.message}</div>`;
  }
}

function closeOutboxModal() {
  document.getElementById("outbox-modal").classList.remove("active");
}

async function showMyKeyModal() {
  const modal = document.getElementById("my-key-modal");
  modal.classList.add("active");
  try {
    const resp = await fetch("/api/identity");
    const data = await resp.json();
    document.getElementById("modal-key-fp").textContent = data.fingerprint;
    document.getElementById("modal-key-pem").textContent = data.public_key_pem;
  } catch (err) {
    document.getElementById("modal-key-pem").textContent = "Failed to load public key.";
  }
}

function closeMyKeyModal() {
  document.getElementById("my-key-modal").classList.remove("active");
}

function formatTimestamp(isoStr) {
  try {
    const dt = new Date(isoStr);
    return dt.toLocaleTimeString() + " (" + dt.toLocaleDateString() + ")";
  } catch (e) {
    return isoStr;
  }
}

function escapeHtml(text) {
  if (!text) return "";
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Custom Modal Dialog Box with "Secure Mail" branding (Replaces native browser alerts)
 */
function showSecureMailAlert(title, message) {
  const modal = document.getElementById("secure-mail-dialog-modal");
  const titleEl = document.getElementById("secure-mail-modal-title-text");
  const bodyEl = document.getElementById("secure-mail-modal-body-text");

  if (!modal || !titleEl || !bodyEl) {
    console.log(`[Secure Mail] ${title}: ${message}`);
    return;
  }

  titleEl.textContent = title || "Secure Mail";
  bodyEl.textContent = message || "";
  modal.classList.add("active");
}

function closeSecureMailAlert() {
  const modal = document.getElementById("secure-mail-dialog-modal");
  if (modal) modal.classList.remove("active");
}
