// ============================================================
// Phishing Detector v2 — Popup Script
// AI + Rule-based + Auto-Detect + Gmail-Aware
// ============================================================

const contentDiv = document.getElementById("content");
const scanBtn = document.getElementById("scanBtn");
const autoToggle = document.getElementById("autoToggle");
const modeBadge = document.getElementById("modeBadge");

// --- Trusted domains ---
const TRUSTED_SENDER_DOMAINS = [
  "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp",
  "google.com", "youtube.com", "gmail.com",
  "microsoft.com", "outlook.com", "live.com",
  "apple.com", "icloud.com",
  "netflix.com", "spotify.com",
  "facebook.com", "meta.com", "instagram.com",
  "twitter.com", "x.com",
  "linkedin.com", "github.com",
  "paypal.com", "stripe.com",
  "flipkart.com", "myntra.com", "swiggy.in", "zomato.com",
  "uber.com", "ola.in",
  "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
  "hdfc.com", "hdfcbank.com", "icicibank.com", "sbi.co.in",
  "notion.so", "slack.com", "zoom.us",
  "dropbox.com", "adobe.com",
];

const TRUSTED_LINK_DOMAINS = [
  ...TRUSTED_SENDER_DOMAINS,
  "amazonaws.com", "cloudfront.net", "awsstatic.com",
  "gstatic.com", "googleapis.com", "googleusercontent.com",
  "akamaized.net", "akamai.net",
  "cloudflare.com", "cdn.jsdelivr.net",
  "office.com", "office365.com",
  "mzstatic.com",
];

function isDomainTrusted(domain, trustedList) {
  domain = domain.toLowerCase();
  return trustedList.some(td => domain === td || domain.endsWith("." + td));
}

function getSenderDomain(sender) {
  if (!sender) return "";
  const match = sender.match(/@([a-zA-Z0-9.-]+)/);
  return match ? match[1].toLowerCase() : "";
}

// ============================================================
// Toggle & Preferences
// ============================================================

function updateModeBadge(autoOn) {
  if (modeBadge) {
    modeBadge.textContent = autoOn ? "Auto Detect ON" : "Scan on Click";
    modeBadge.className = "mode-badge " + (autoOn ? "auto" : "manual");
  }
}

// Load saved preference
chrome.storage.local.get({ autoDetect: false }, (prefs) => {
  autoToggle.checked = prefs.autoDetect;
  updateModeBadge(prefs.autoDetect);
});

// Save preference on toggle — and trigger immediate scan if turned ON
autoToggle.addEventListener("change", async () => {
  const autoOn = autoToggle.checked;
  chrome.storage.local.set({ autoDetect: autoOn });
  updateModeBadge(autoOn);

  if (autoOn) {
    // Tell the content script on the active tab to scan right now
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        chrome.tabs.sendMessage(tab.id, { action: "AUTO_SCAN" }).catch(() => {});
      }
    } catch {}
  }
});

// ============================================================
// UI Helpers
// ============================================================

function showLoading() {
  contentDiv.innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <p class="loading-text">Analyzing content with AI...</p>
    </div>
  `;
}

function showError(message) {
  contentDiv.innerHTML = `
    <div class="error-message">
      <p>${message}</p>
      <button class="scan-btn" id="retryBtn">Try Again</button>
    </div>
  `;
  document.getElementById("retryBtn").addEventListener("click", scanPage);
}

function showResult(result) {
  const { score, status, explanation, signals, urlFindings, aiReason, aiStatus, aiDiagnostic, ruleScore, aiScore } = result;

  let statusClass = "safe";
  if (status === "Suspicious") statusClass = "suspicious";
  if (status === "Phishing") statusClass = "phishing";

  // Score breakdown
  let breakdownHtml = "";
  if (ruleScore !== undefined || aiScore !== undefined) {
    breakdownHtml = `<div class="score-breakdown">
      <div class="score-item">
        <div class="label">Rules</div>
        <div class="value">${ruleScore ?? "—"}</div>
      </div>
      <div class="score-item">
        <div class="label">AI</div>
        <div class="value">${aiScore >= 0 ? aiScore : "—"}</div>
      </div>
      <div class="score-item">
        <div class="label">Final</div>
        <div class="value" style="color:#fff">${score}</div>
      </div>
    </div>`;
  }

  // Rule signals
  let signalsHtml = "";
  if (signals && signals.length > 0) {
    signalsHtml = `<div class="signals-list">
      <p class="signals-title">Detected Signals</p>
      ${signals.map(s => `<div class="signal-item ${s.severity || ''}">${s.label}</div>`).join("")}
    </div>`;
  }

  // URL findings
  let urlHtml = "";
  if (urlFindings && urlFindings.length > 0) {
    urlHtml = `<div class="signals-list">
      <p class="signals-title">Link Analysis</p>
      ${urlFindings.map(f => `<div class="signal-item ${f.severity}">${f.label}</div>`).join("")}
    </div>`;
  }

  // AI Analysis section
  let aiHtml = "";
  if (aiReason && aiReason !== "AI unavailable") {
    const aiClass = (aiStatus || status).toLowerCase();
    const displayStatus = aiStatus || status;
    aiHtml = `<div class="ai-section">
      <p class="ai-label">AI Analysis</p>
      <p class="ai-status ${aiClass === "phishing" ? "phishing" : aiClass === "suspicious" ? "suspicious" : "safe"}">${displayStatus}</p>
      <p class="ai-reason">${aiReason}</p>
    </div>`;
  } else if (aiReason === "AI unavailable") {
    const diagnosticHtml = aiDiagnostic
      ? `<p class="ai-fallback" style="margin-top:6px;color:#ffd166;">${aiDiagnostic}</p>`
      : "";
    aiHtml = `<p class="ai-fallback">AI unavailable — using rule-based detection only</p>${diagnosticHtml}`;
  }

  contentDiv.innerHTML = `
    <div class="result-card">
      <div class="score-circle ${statusClass}">${score}</div>
      <div class="status-label ${statusClass}">${status}</div>
      <p class="explanation">${explanation}</p>
      ${breakdownHtml}
      ${signalsHtml}
      ${urlHtml}
      ${aiHtml}
    </div>
    <button class="scan-btn" id="rescanBtn">Scan Again</button>
  `;
  document.getElementById("rescanBtn").addEventListener("click", scanPage);
}

// ============================================================
// Content Extraction (injected into page)
// ============================================================

function extractGmailContent() {
  const url = window.location.href;
  const isGmail = url.includes("mail.google.com");

  if (!isGmail) {
    return {
      text: (document.body.innerText || "").substring(0, 5000).trim(),
      links: Array.from(document.querySelectorAll("a[href]"))
        .map(a => a.href)
        .filter(h => h.startsWith("http"))
        .slice(0, 20),
      isGmail: false,
      sender: null,
      subject: null,
    };
  }

  let emailText = "";
  let sender = "";
  let subject = "";
  let links = [];

  const subjectEl = document.querySelector("h2.hP") || document.querySelector("[data-thread-perm-id] h2");
  if (subjectEl) subject = subjectEl.innerText.trim();

  const senderEl = document.querySelector(".gD") || document.querySelector("[email]");
  if (senderEl) {
    sender = senderEl.getAttribute("email") || senderEl.innerText.trim();
  }
  if (!sender) {
    const fromSpan = document.querySelector("span.go");
    if (fromSpan) sender = fromSpan.innerText.trim();
  }

  const emailBodies = document.querySelectorAll(".a3s.aiL, .a3s.aXjCH, .a3s, .ii.gt");
  if (emailBodies.length > 0) {
    const bodyTexts = [];
    emailBodies.forEach(el => {
      const t = el.innerText.trim();
      if (t.length > 20) bodyTexts.push(t);
    });
    bodyTexts.sort((a, b) => b.length - a.length);
    emailText = bodyTexts[0] || "";
  }

  if (!emailText) {
    const msgContainer = document.querySelector(".nH.aHU") || document.querySelector("[role='main'] .nH");
    if (msgContainer) emailText = msgContainer.innerText.trim();
  }

  if (!emailText) {
    const messageEls = document.querySelectorAll("[data-message-id]");
    if (messageEls.length > 0) {
      emailText = messageEls[messageEls.length - 1].innerText.trim();
    }
  }

  const bodyContainer = document.querySelector(".a3s.aiL") || document.querySelector(".a3s") || document.querySelector(".ii.gt");
  if (bodyContainer) {
    links = Array.from(bodyContainer.querySelectorAll("a[href]"))
      .map(a => a.href)
      .filter(h => h.startsWith("http") && !h.includes("mail.google.com"))
      .slice(0, 30);

    const resolved = [];
    links.forEach(lnk => {
      if (lnk.includes("google.com/url")) {
        try {
          const u = new URL(lnk);
          const dest = u.searchParams.get("q") || u.searchParams.get("url");
          if (dest && dest.startsWith("http")) resolved.push(dest);
        } catch {}
      }
    });
    links = links.filter(l => !l.includes("google.com/url")).concat(resolved);
  }

  let fullText = "";
  if (subject) fullText += "Subject: " + subject + "\n";
  if (sender) fullText += "From: " + sender + "\n";
  fullText += "\n" + emailText;

  return {
    text: fullText.substring(0, 5000).trim(),
    links: [...new Set(links)],
    isGmail: true,
    sender,
    subject,
  };
}

// ============================================================
// Phishing Detection — Rule-Based Heuristics
// ============================================================

const PHISHING_SIGNALS = {
  urgentWords: /\b(urgent|immediately|suspend(?:ed)?|act now|limited time|within 24 hours|within 48 hours|account will be closed|account will be locked|final warning|last chance)\b/gi,
  suspiciousDomains: /\b(bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|shorturl|0x[a-f0-9]{6,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/gi,
  fakeAuth: /\b(enter your password|provide your ssn|enter your credit card|send your bank account|provide your routing number|enter your pin|share your login credentials|confirm your identity by)\b/gi,
  spoofedBrands: /\b(paypal|wells fargo|bank of america|citibank|chase bank|western union)\b/gi,
  obfuscatedUrls: /(https?:\/\/[^\s]*@[^\s]*\.[a-z]|xn--)/gi,
  threatPatterns: /\b(dear customer|dear user|click below to verify|update your payment method immediately|verify your account now|has been compromised|unusual sign-?in|suspicious login attempt|security alert.*action required)\b/gi,
  grammarIssues: /\b(kindly|do the needful|revert back|same has been|please to|dear valued)\b/gi,
};

const CHECK_DEFS = [
  { key: "urgentWords", label: "Urgency / pressure language", weight: 15, severity: "high" },
  { key: "suspiciousDomains", label: "Suspicious or shortened URLs", weight: 20, severity: "high" },
  { key: "fakeAuth", label: "Requests for sensitive data", weight: 22, severity: "high" },
  { key: "spoofedBrands", label: "Brand impersonation", weight: 10, severity: "medium" },
  { key: "obfuscatedUrls", label: "Obfuscated or deceptive links", weight: 25, severity: "high" },
  { key: "threatPatterns", label: "Common phishing templates", weight: 14, severity: "medium" },
  { key: "grammarIssues", label: "Suspicious grammar patterns", weight: 8, severity: "low" },
];

// ============================================================
// URL Analysis
// ============================================================

function analyzeUrl(rawUrl) {
  let urlStr = rawUrl.trim();
  if (!/^https?:\/\//i.test(urlStr)) urlStr = "http://" + urlStr;
  let parsed;
  try { parsed = new URL(urlStr); } catch { return null; }

  const domain = parsed.hostname;
  if (isDomainTrusted(domain, TRUSTED_LINK_DOMAINS)) {
    return { score: 0, findings: [] };
  }

  const parts = domain.split(".");
  const findings = [];
  let riskPts = 0;

  if (parsed.protocol === "http:") {
    findings.push({ label: "Insecure protocol (HTTP)", severity: "high" });
    riskPts += 20;
  }
  if (rawUrl.includes("@")) {
    findings.push({ label: "Contains @ — hides real destination", severity: "high" });
    riskPts += 30;
  }
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    findings.push({ label: "IP address instead of domain", severity: "high" });
    riskPts += 25;
  }
  if (/\d/.test(parts.slice(-2, -1)[0] || "")) {
    findings.push({ label: "Numbers in domain — possible typosquat", severity: "medium" });
    riskPts += 15;
  }
  const subdomains = parts.length > 2 ? parts.slice(0, -2) : [];
  if (subdomains.length >= 3) {
    findings.push({ label: `${subdomains.length} subdomains — abnormally deep`, severity: "medium" });
    riskPts += 15;
  }
  if (/^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|shorturl\.at|is\.gd|v\.gd)$/i.test(domain)) {
    findings.push({ label: "Known URL shortener", severity: "medium" });
    riskPts += 20;
  }
  if (/\.(xyz|top|click|loan|work|gq|ml|cf|tk|buzz|rest|support)$/i.test(domain)) {
    findings.push({ label: "Suspicious TLD", severity: "medium" });
    riskPts += 15;
  }
  if ((domain.match(/-/g) || []).length >= 3) {
    findings.push({ label: "Excessive hyphens in domain", severity: "medium" });
    riskPts += 15;
  }

  return { score: Math.min(riskPts, 100), findings };
}

// ============================================================
// AI Detection via background service worker
// ============================================================

async function aiDetect(text, sender, links) {
  try {
    const result = await chrome.runtime.sendMessage({
      action: "AI_DETECT",
      text: text,
      senderEmail: sender || "",
      links: links || [],
    });
    return result || { score: -1, status: "Unknown", reason: "AI unavailable" };
  } catch (err) {
    console.warn("AI detection failed:", err);
    return {
      score: -1,
      status: "Unknown",
      reason: "AI unavailable",
      diagnostic: String(err?.message || ""),
    };
  }
}

// ============================================================
// Combined Analysis
// ============================================================

async function analyzeContent(text, links, sender) {
  if (!text || text.trim().length < 10) return null;

  const senderDomain = getSenderDomain(sender);
  const senderTrusted = senderDomain && isDomainTrusted(senderDomain, TRUSTED_SENDER_DOMAINS);

  // 1. Rule-based
  let rawScore = 0;
  const matchedSignals = [];

  CHECK_DEFS.forEach(({ key, label, weight, severity }) => {
    const matches = text.match(PHISHING_SIGNALS[key]);
    if (matches && matches.length > 0) {
      const count = matches.length;
      let pts = Math.min(weight * Math.min(count, 3), weight * 2);
      if (senderTrusted) pts = pts * 0.15;
      rawScore += pts;
      matchedSignals.push({ label: `${label} (${count}x)`, severity });
    }
  });

  if ((text.match(/!/g) || []).length > 5) {
    rawScore += senderTrusted ? 1 : 5;
    matchedSignals.push({ label: "Excessive exclamation marks", severity: "low" });
  }

  const ruleScore = Math.min(Math.round(rawScore), 100);

  // 2. URL analysis
  let urlScore = 0;
  const allUrlFindings = [];
  if (links && links.length > 0) {
    for (const link of links) {
      const result = analyzeUrl(link);
      if (result && result.score > 0) {
        urlScore = Math.max(urlScore, result.score);
        result.findings.forEach(f => {
          if (!allUrlFindings.find(x => x.label === f.label)) {
            allUrlFindings.push(f);
          }
        });
      }
    }
  }

  // 3. AI analysis
  const ai = await aiDetect(text, sender, links);
  const aiAvailable = ai.score >= 0;

  // 4. Combine scores
  let finalScore;
  if (aiAvailable) {
    if (senderTrusted) {
      finalScore = Math.round(ruleScore * 0.10 + urlScore * 0.05 + ai.score * 0.85);
    } else {
      finalScore = Math.round(ruleScore * 0.25 + urlScore * 0.20 + ai.score * 0.55);
    }
  } else {
    if (senderTrusted) {
      finalScore = Math.round(ruleScore * 0.3 + urlScore * 0.2);
    } else {
      finalScore = Math.round(ruleScore * 0.6 + urlScore * 0.4);
    }
  }

  finalScore = Math.min(finalScore, 100);
  const status = finalScore >= 65 ? "Phishing" : finalScore >= 30 ? "Suspicious" : "Safe";

  let explanation;
  if (status === "Safe") {
    explanation = "This content appears safe. No significant phishing indicators detected.";
  } else if (status === "Suspicious") {
    explanation = "Some phishing indicators found. Be cautious with any links or requests.";
  } else {
    explanation = "Multiple phishing indicators detected. Do NOT click links or provide personal information.";
  }

  const displaySignals = senderTrusted && finalScore < 30 ? [] : matchedSignals;

  return {
    score: finalScore,
    status,
    explanation,
    signals: displaySignals,
    urlFindings: allUrlFindings,
    aiReason: ai.reason,
    aiStatus: aiAvailable ? ai.status : null,
    aiDiagnostic: ai.diagnostic || "",
    aiScore: aiAvailable ? ai.score : -1,
    ruleScore,
  };
}

// ============================================================
// Main Scan
// ============================================================

async function scanPage() {
  showLoading();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Try content script message first (works if content script is injected)
    let extracted = null;
    try {
      extracted = await chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_CONTENT" });
    } catch {
      // Content script not available — fall back to executeScript
    }

    if (!extracted) {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: extractGmailContent,
      });
      extracted = results[0]?.result;
    }

    if (!extracted || !extracted.text || extracted.text.trim().length < 10) {
      if (extracted?.isGmail) {
        showError("No email is open. Please open an email in Gmail and try again.");
      } else {
        showError("No content found on this page.");
      }
      return;
    }

    const result = await analyzeContent(extracted.text, extracted.links, extracted.sender);

    if (!result) {
      showError("Could not analyze content.");
      return;
    }

    // Store result for background access
    chrome.storage.local.set({ lastResult: result, lastUrl: tab.url });
    showResult(result);
  } catch (error) {
    console.error("Scan error:", error);
    showError("Could not scan this page. Make sure you're on a regular webpage.");
  }
}

// ============================================================
// Listen for auto-scan results from content script
// ============================================================

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "CONTENT_EXTRACTED" && msg.data) {
    // Content script extracted content — analyze it
    showLoading();
    analyzeContent(msg.data.text, msg.data.links, msg.data.sender).then(result => {
      if (result) {
        chrome.storage.local.set({ lastResult: result });
        showResult(result);
      }
    });
  }
});

// ============================================================
// Init — check for cached auto-scan result
// ============================================================

async function init() {
  // Check if there's a recent auto-scan result for the current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.storage.local.get(["lastResult", "lastUrl", "autoDetect"], (data) => {
    if (data.autoDetect && data.lastResult && data.lastUrl === tab.url) {
      showResult(data.lastResult);
    }
  });
}

scanBtn.addEventListener("click", scanPage);
init();
