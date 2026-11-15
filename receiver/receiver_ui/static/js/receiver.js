/**
 * Receiver Dashboard Client Logic (Laptop 2)
 */

let currentMessageId = null;
let pollInterval = null;
let knownMessageIds = new Set();
let isInitialLoad = true;

// Override window.alert so that ANY popup dialog box displays "Secure Mail" instead of "Antigravity"
window.alert = function(msg) {
  showSecureMailAlert("Secure Mail", msg);
};

document.addEventListener("DOMContentLoaded", () => {
  loadInbox();
  // Poll for new incoming transmissions every 3.5 seconds
  pollInterval = setInterval(loadInbox, 3500);
});

async function loadInbox() {
  const container = document.getElementById("inbox-list");
  try {
    const resp = await fetch("/api/inbox");
    const data = await resp.json();

    if (!data.messages || data.messages.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.85rem;">
          <i class="fa-solid fa-satellite-dish" style="font-size: 1.5rem; margin-bottom: 0.5rem; display: block; color: var(--accent-green);"></i>
          No messages received yet.<br>Listening on port 5000 for transmissions from Laptop 1...
        </div>
      `;
      return;
    }

    // Check for newly arrived messages to trigger the "Secure Mail" drop-box notification
    if (!isInitialLoad) {
      for (const m of data.messages) {
        if (!knownMessageIds.has(m.message_id)) {
          triggerSecureMailDropBox(m);
        }
      }
    }

    // Update set of known message IDs
    data.messages.forEach(m => knownMessageIds.add(m.message_id));
    isInitialLoad = false;

    container.innerHTML = data.messages.map(m => {
      let badgeClass = "badge-success";
      let statusText = m.verification_status;

      if (statusText === "AUTHENTICATED") {
        badgeClass = "badge-success";
      } else if (statusText.includes("INTEGRITY") || statusText.includes("TAMPERED")) {
        badgeClass = "badge-danger";
      } else if (statusText.includes("SIGNATURE") || statusText.includes("INVALID")) {
        badgeClass = "badge-danger";
      } else if (statusText.includes("REPLAY")) {
        badgeClass = "badge-warning";
      } else {
        badgeClass = "badge-info";
      }

      const isSelected = (currentMessageId === m.message_id) ? "active" : "";

      return `
        <div class="inbox-item ${isSelected}" onclick="inspectMessage('${m.message_id}')">
          <div class="inbox-item-header">
            <span class="inbox-sender">${escapeHtml(m.sender_id)}</span>
            <span class="badge ${badgeClass}">${statusText}</span>
          </div>
          <div class="inbox-subject">${escapeHtml(m.subject)}</div>
          <div class="inbox-time" style="margin-top: 4px;">
            <i class="fa-regular fa-clock"></i> ${formatTimestamp(m.received_at)}
          </div>
        </div>
      `;
    }).join("");

    // If a message was already selected, update its display smoothly
    if (!currentMessageId && data.messages.length > 0) {
      inspectMessage(data.messages[0].message_id);
    }
  } catch (err) {
    console.error("Failed to load inbox:", err);
  }
}

/**
 * Animated Drop-Box Notification that slides down from top-right when any email arrives
 * Clearly branded as "Secure Mail"
 */
function triggerSecureMailDropBox(msg) {
  const container = document.getElementById("secure-mail-dropbox-container");
  if (!container) return;

  const isTampered = (msg.verification_status !== "AUTHENTICATED");
  const tamperedClass = isTampered ? "tampered" : "";
  const icon = isTampered ? "fa-triangle-exclamation" : "fa-shield-halved";
  const headerTitle = isTampered ? "Secure Mail — Tamper Attack Detected" : "Secure Mail — New Encrypted Message";
  const badgeClass = isTampered ? "badge-danger" : "badge-success";

  const box = document.createElement("div");
  box.className = `secure-mail-dropbox ${tamperedClass}`;
  box.innerHTML = `
    <div class="dropbox-header">
      <div class="dropbox-title">
        <i class="fa-solid ${icon}"></i>
        <span>${headerTitle}</span>
      </div>
      <button class="dropbox-close" onclick="event.stopPropagation(); this.closest('.secure-mail-dropbox').remove();">&times;</button>
    </div>
    <div class="dropbox-body">
      <div><strong>From:</strong> ${escapeHtml(msg.sender_id)}</div>
      <div><strong>Subject:</strong> ${escapeHtml(msg.subject)}</div>
    </div>
    <div class="dropbox-meta">
      <span class="badge ${badgeClass}">${msg.verification_status}</span>
      <span>Click to inspect & decrypt</span>
    </div>
  `;

  box.onclick = () => {
    inspectMessage(msg.message_id);
    box.remove();
  };

  container.appendChild(box);

  // Automatically fade out after 8 seconds
  setTimeout(() => {
    if (box.parentNode) {
      box.style.opacity = "0";
      box.style.transform = "translateY(-20px)";
      setTimeout(() => box.remove(), 400);
    }
  }, 8000);
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

async function inspectMessage(messageId) {
  currentMessageId = messageId;
  const emptyView = document.getElementById("inspector-empty");
  const contentView = document.getElementById("inspector-content");
  emptyView.style.display = "none";
  contentView.style.display = "block";

  try {
    const resp = await fetch(`/api/inbox/${messageId}`);
    const data = await resp.json();
    const msg = data.message;
    const envelope = data.envelope;

    // Header info
    document.getElementById("detail-sender").textContent = msg.sender_id;
    document.getElementById("detail-subject").textContent = msg.subject;
    document.getElementById("detail-timestamp").textContent = `${formatTimestamp(msg.timestamp)} (Received: ${formatTimestamp(msg.received_at)})`;
    document.getElementById("detail-msg-id").textContent = msg.message_id;

    // Overall Status Badge
    const detailStatusBadge = document.getElementById("detail-status-badge");
    detailStatusBadge.textContent = msg.verification_status;
    if (msg.verification_status === "AUTHENTICATED") {
      detailStatusBadge.className = "badge badge-success";
    } else {
      detailStatusBadge.className = "badge badge-danger";
    }

    // 4 Security Pillars Badges
    setPillarBadge("pillar-confidentiality", "AES-256-GCM + OAEP", "PASSED", "badge-success");

    if (msg.integrity_status === "PASSED") {
      setPillarBadge("pillar-integrity", "Auth Tag & Hash", "VERIFIED", "badge-success");
    } else {
      setPillarBadge("pillar-integrity", "Auth Tag & Hash", "TAMPERED", "badge-danger");
    }

    if (msg.signature_status === "PASSED") {
      setPillarBadge("pillar-auth", "RSA-PSS Valid", "AUTHENTICATED", "badge-success");
    } else {
      setPillarBadge("pillar-auth", "Signature Corrupted", "INVALID", "badge-danger");
    }

    if (msg.non_repudiation_status === "PASSED") {
      setPillarBadge("pillar-nonrep", "Sender Key Verified", "CONFIRMED", "badge-success");
    } else {
      setPillarBadge("pillar-nonrep", "Unverified", "FAILED", "badge-danger");
    }

    // Decrypted Content Box
    const decryptedBox = document.getElementById("decrypted-box");
    const decryptedText = document.getElementById("decrypted-text");
    const decryptedBadge = document.getElementById("decrypted-badge");

    if (msg.verification_status === "AUTHENTICATED" && msg.decrypted_body) {
      decryptedBox.className = "decrypted-msg-box";
      decryptedBadge.className = "badge badge-success";
      decryptedBadge.textContent = "DECRYPTED & AUTHENTICATED";
      decryptedText.innerHTML = `<span style="color: #34d399; font-weight: 500;">${escapeHtml(msg.decrypted_body)}</span>`;
    } else {
      decryptedBox.className = "decrypted-msg-box tampered";
      decryptedBadge.className = "badge badge-danger";
      decryptedBadge.textContent = "SECURITY BLOCKED";
      decryptedText.innerHTML = `
        <div style="color: #f87171; font-weight: bold; margin-bottom: 6px;">
          <i class="fa-solid fa-triangle-exclamation"></i> DECRYPTION / VERIFICATION FAILURE!
        </div>
        <div style="color: #cbd5e1; font-size: 0.85rem;">
          ${escapeHtml(msg.error_message || "Message verification failed. Content withheld for security.")}
        </div>
      `;
    }

    // Render Audit Trail
    renderAuditTrail(msg);

    // Raw Wire Envelope JSON
    document.getElementById("raw-envelope-dump").textContent = JSON.stringify(envelope, null, 2);

  } catch (err) {
    console.error("Error inspecting message:", err);
  }
}

function setPillarBadge(elementId, algoText, statusText, badgeClass) {
  const el = document.getElementById(elementId);
  el.className = `badge ${badgeClass}`;
  el.textContent = statusText;
}

function renderAuditTrail(msg) {
  const list = document.getElementById("audit-steps-list");
  const isSuccess = (msg.verification_status === "AUTHENTICATED");

  const steps = [
    {
      step: "1. Replay Protection & Timestamp Freshness",
      passed: !msg.verification_status.includes("REPLAY") && !msg.verification_status.includes("EXPIRED"),
      desc: "UUIDv4 message_id freshness verified against SQLite replay cache. Timestamp within 300s window."
    },
    {
      step: "2. RSA-OAEP Session Key Decryption",
      passed: !msg.verification_status.includes("KEY_DECRYPTION"),
      desc: "Decrypted 256-bit AES session key using Laptop 2's local RSA private key with SHA-256 OAEP padding."
    },
    {
      step: "3. AES-256-GCM AEAD Tag & Header Integrity",
      passed: (msg.integrity_status === "PASSED"),
      desc: "Validated 128-bit authentication tag and Associated Authenticated Data (AAD: subject, sender, timestamp)."
    },
    {
      step: "4. SHA-256 Plaintext Hash Digest",
      passed: (msg.integrity_status === "PASSED"),
      desc: `Computed SHA-256 hash (${msg.sha256_hash ? msg.sha256_hash.substring(0, 16) + '...' : 'N/A'}) matches wire payload.`
    },
    {
      step: "5. RSA-PSS Digital Signature Verification",
      passed: (msg.signature_status === "PASSED"),
      desc: "Verified RSA-PSS signature with maximal salt and SHA-256. Proves sender authenticity and non-repudiation."
    },
    {
      step: "6. Sender Public Key Fingerprint Trust",
      passed: (msg.sender_trusted_status !== "SPOOFED" && msg.sender_trusted_status !== "KEY_CHANGED_WARNING"),
      desc: `Fingerprint evaluated against trusted public key directory.`
    }
  ];

  list.innerHTML = steps.map(s => {
    const badge = s.passed ? `<span class="badge badge-success">PASSED</span>` : `<span class="badge badge-danger">FAILED</span>`;
    return `
      <div class="audit-item">
        <div>
          <div class="audit-step-name">${s.step}</div>
          <div class="audit-step-desc">${s.desc}</div>
        </div>
        <div>${badge}</div>
      </div>
    `;
  }).join("");
}

async function simulateAttack(attackType) {
  if (!currentMessageId) {
    alert("Please select a message to test.");
    return;
  }

  try {
    const resp = await fetch("/api/tamper_simulation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message_id: currentMessageId,
        attack_type: attackType
      })
    });

    const data = await resp.json();

    const attackNames = {
      "tamper_ciphertext": "Ciphertext Tampering (Bit Flip)",
      "tamper_signature": "Signature Corruption / Forgery",
      "tamper_subject": "Header / Subject Tampering (AAD Mismatch)",
      "replay_attack": "Duplicate Message Replay Attack"
    };

    const friendlyName = attackNames[attackType] || attackType;

    let alertMsg = `SECURITY DEFENSE TEST TRIGGERED!\n\n`;
    alertMsg += `Attack Vector: ${friendlyName}\n`;
    alertMsg += `Defense Intercepted: ${data.defense_triggered ? "YES (ATTACK BLOCKED)" : "NO"}\n`;
    alertMsg += `Verification Status: ${data.verification_status}\n`;
    alertMsg += `Security Alert: ${data.error_message || "Attack intercepted."}\n\n`;
    alertMsg += `Notice how the cryptographic barriers prevent compromised messages from being accepted or decrypted!`;

    alert(alertMsg);
  } catch (err) {
    alert(`Error executing simulation: ${err.message}`);
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert(`Copied to clipboard:\n${text}`);
  }).catch(() => {
    prompt("Copy text manually:", text);
  });
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

async function showTrustedSendersModal() {
  const modal = document.getElementById("trusted-senders-modal");
  const container = document.getElementById("trusted-senders-list");
  modal.classList.add("active");
  container.innerHTML = "Loading trusted senders directory...";

  try {
    const resp = await fetch("/api/trusted_senders");
    const data = await resp.json();

    if (!data.senders || data.senders.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 1.5rem;">
          No senders registered yet. Senders are automatically added upon their first authenticated transmission.
        </div>`;
      return;
    }

    container.innerHTML = data.senders.map(s => `
      <div class="identity-badge-box">
        <div class="id-field">
          <span class="id-label">Sender Email:</span>
          <span class="id-val" style="color: var(--accent-cyan);">${escapeHtml(s.sender_id)}</span>
        </div>
        <div class="id-field">
          <span class="id-label">Added At:</span>
          <span class="id-val" style="font-size: 0.78rem;">${formatTimestamp(s.added_at)}</span>
        </div>
        <div class="id-field" style="margin-top: 4px;">
          <span class="id-label">Verified SHA-256 Fingerprint:</span>
        </div>
        <div class="fingerprint-text">${escapeHtml(s.fingerprint)}</div>
      </div>
    `).join("");
  } catch (err) {
    container.innerHTML = `<div style="color: var(--accent-red);">Error loading senders: ${err.message}</div>`;
  }
}

function closeTrustedSendersModal() {
  document.getElementById("trusted-senders-modal").classList.remove("active");
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
