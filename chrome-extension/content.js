// ============================================================
// Content Script — Gmail Auto-Detection & In-Page Overlay
// ============================================================

(() => {
  let lastScannedText = "";
  let scanTimeout = null;
  let overlayEl = null;
  let scanInProgress = false;
  let activeScanKey = "";
  let lastCompletedScanKey = "";
  let lastCompletedScanAt = 0;
  let lastDisplayedScanKey = "";
  let lastDisplayedScanAt = 0;

  const DUPLICATE_SCAN_WINDOW_MS = 12000;
  let previouslyOpenEmail = false;

  // ============================================================
  // Gmail View Detection — only analyze when a single email is open
  // ============================================================

  function isEmailOpen() {
    // Gmail uses hash-based routing:
    //   #inbox            → inbox list (DO NOT scan)
    //   #inbox/FMfcg...   → opened email (SCAN)
    //   #sent             → sent list (DO NOT scan)
    //   #sent/FMfcg...    → opened sent email (SCAN)
    //   #search/...       → search results (DO NOT scan)
    //   #label/...        → label view (DO NOT scan)
    const hash = window.location.hash;

    // Must have a message ID segment after the view name
    // Gmail message IDs look like: #inbox/FMfcgz... or #all/FMfcgz...
    const hasMessageId = /^#[a-zA-Z]+\/[A-Za-z0-9]+/.test(hash);
    if (!hasMessageId) return false;

    // Verify the email body container is present in the DOM
    // .a3s is Gmail's email body class; h2.hP is the subject heading
    const hasEmailBody = !!(
      document.querySelector(".a3s.aiL") ||
      document.querySelector(".a3s.aXjCH") ||
      document.querySelector(".a3s") ||
      document.querySelector(".ii.gt")
    );
    const hasSubject = !!document.querySelector("h2.hP");

    // Both a message-style URL and actual rendered email content must be present
    return hasEmailBody && hasSubject;
  }

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

  function isDomainTrusted(domain, list) {
    domain = domain.toLowerCase();
    return list.some(td => domain === td || domain.endsWith("." + td));
  }

  function getSenderDomain(sender) {
    if (!sender) return "";
    const m = sender.match(/@([a-zA-Z0-9.-]+)/);
    return m ? m[1].toLowerCase() : "";
  }

  // ============================================================
  // Gmail Content Extraction
  // ============================================================

  function extractGmailContent() {
    let emailText = "";
    let sender = "";
    let subject = "";
    let links = [];

    const subjectEl = document.querySelector("h2.hP") || document.querySelector("[data-thread-perm-id] h2");
    if (subjectEl) subject = subjectEl.innerText.trim();

    const senderEl = document.querySelector(".gD") || document.querySelector("[email]");
    if (senderEl) sender = senderEl.getAttribute("email") || senderEl.innerText.trim();
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
      if (messageEls.length > 0) emailText = messageEls[messageEls.length - 1].innerText.trim();
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
      sender,
      subject,
    };
  }

  function getScanKey(content) {
    const preview = (content?.text || "").replace(/\s+/g, " ").trim().slice(0, 180);
    return [
      content?.sender || "",
      content?.subject || "",
      preview,
    ].join("||");
  }

  function scheduleAutoScan(delay = 0) {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
      chrome.storage.local.get({ autoDetect: false }, (prefs) => {
        if (prefs.autoDetect) autoScan();
      });
    }, delay);
  }

  // ============================================================
  // Rule-Based Detection
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
    { key: "urgentWords", label: "Urgency language", weight: 15 },
    { key: "suspiciousDomains", label: "Suspicious URLs", weight: 20 },
    { key: "fakeAuth", label: "Requests sensitive data", weight: 22 },
    { key: "spoofedBrands", label: "Brand impersonation", weight: 10 },
    { key: "obfuscatedUrls", label: "Obfuscated links", weight: 25 },
    { key: "threatPatterns", label: "Phishing templates", weight: 14 },
    { key: "grammarIssues", label: "Suspicious grammar", weight: 8 },
  ];

  function analyzeUrl(rawUrl) {
    let urlStr = rawUrl.trim();
    if (!/^https?:\/\//i.test(urlStr)) urlStr = "http://" + urlStr;
    let parsed;
    try { parsed = new URL(urlStr); } catch { return null; }
    const domain = parsed.hostname;
    if (isDomainTrusted(domain, TRUSTED_LINK_DOMAINS)) return { score: 0 };

    let riskPts = 0;
    if (parsed.protocol === "http:") riskPts += 20;
    if (rawUrl.includes("@")) riskPts += 30;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) riskPts += 25;
    const parts = domain.split(".");
    if (/\d/.test(parts.slice(-2, -1)[0] || "")) riskPts += 15;
    if (parts.length > 4) riskPts += 15;
    if (/^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|shorturl\.at|is\.gd|v\.gd)$/i.test(domain)) riskPts += 20;
    if (/\.(xyz|top|click|loan|work|gq|ml|cf|tk|buzz|rest|support)$/i.test(domain)) riskPts += 15;

    return { score: Math.min(riskPts, 100) };
  }

  // ============================================================
  // AI Detection — routed through background script (avoids CORS)
  // ============================================================

  async function aiDetect(text, senderEmail, links) {
    try {
      const result = await chrome.runtime.sendMessage({
        action: "AI_DETECT",
        text: text,
        senderEmail: senderEmail || "",
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
  // Full Analysis
  // ============================================================

  async function fullAnalysis(content) {
    const { text, links, sender } = content;
    if (!text || text.trim().length < 20) return null;

    const senderDomain = getSenderDomain(sender);
    const senderTrusted = senderDomain && isDomainTrusted(senderDomain, TRUSTED_SENDER_DOMAINS);

    // Rule-based
    let rawScore = 0;
    CHECK_DEFS.forEach(({ key, weight }) => {
      const matches = text.match(PHISHING_SIGNALS[key]);
      if (matches) {
        let pts = Math.min(weight * Math.min(matches.length, 3), weight * 2);
        if (senderTrusted) pts *= 0.15;
        rawScore += pts;
      }
    });
    const ruleScore = Math.min(Math.round(rawScore), 100);

    // URL analysis
    let urlScore = 0;
    if (links && links.length > 0) {
      for (const link of links) {
        const r = analyzeUrl(link);
        if (r) urlScore = Math.max(urlScore, r.score);
      }
    }

    // AI analysis
    const ai = await aiDetect(text, sender, links);
    const aiOk = ai.score >= 0;

    // Combine
    let finalScore;
    if (aiOk) {
      finalScore = senderTrusted
        ? Math.round(ruleScore * 0.10 + urlScore * 0.05 + ai.score * 0.85)
        : Math.round(ruleScore * 0.25 + urlScore * 0.20 + ai.score * 0.55);
    } else {
      finalScore = senderTrusted
        ? Math.round(ruleScore * 0.3 + urlScore * 0.2)
        : Math.round(ruleScore * 0.6 + urlScore * 0.4);
    }
    finalScore = Math.min(finalScore, 100);

    const status = finalScore >= 65 ? "Phishing" : finalScore >= 30 ? "Suspicious" : "Safe";

    return {
      score: finalScore,
      status,
      aiReason: ai.reason,
      aiStatus: aiOk ? ai.status : null,
      aiDiagnostic: ai.diagnostic || "",
      ruleScore,
      aiScore: aiOk ? ai.score : -1,
    };
  }

  // ============================================================
  // In-Page Overlay (shows on Gmail page itself)
  // ============================================================

  function removeOverlay() {
    if (overlayEl) {
      overlayEl.remove();
      overlayEl = null;
    }
  }

  function showOverlay(result) {
    removeOverlay();

    const { score, status, aiReason, aiStatus, aiDiagnostic, ruleScore, aiScore } = result;

    const colors = {
      Safe: { bg: "#0d3320", border: "#00c853", text: "#00e676", icon: "&#10003;" },
      Suspicious: { bg: "#3e2e00", border: "#ffd600", text: "#ffea00", icon: "&#9888;" },
      Phishing: { bg: "#3e0a0a", border: "#ff1744", text: "#ff5252", icon: "&#10007;" },
    };
    const c = colors[status] || colors.Safe;

    overlayEl = document.createElement("div");
    overlayEl.id = "phishing-detector-overlay";

    let aiLine = aiReason && aiReason !== "AI unavailable"
      ? `<div style="margin-top:8px;padding:8px 10px;background:rgba(108,99,255,0.1);border-radius:6px;border:1px solid rgba(108,99,255,0.25);">
           <div style="font-size:10px;color:#7c75e6;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:3px;">AI Analysis</div>
           <div style="font-size:12px;color:#b0b0ff;line-height:1.4;">${aiReason}</div>
         </div>`
      : aiReason === "AI unavailable"
        ? `<div style="margin-top:6px;font-size:11px;color:#ff9800;font-style:italic;">AI unavailable — rule-based detection only</div>`
        : "";

    if (aiReason === "AI unavailable" && aiDiagnostic) {
      aiLine += `<div style="margin-top:6px;font-size:11px;color:#ffd166;line-height:1.4;">${aiDiagnostic}</div>`;
    }

    const scoreBreakdown = `<div style="display:flex;gap:12px;margin-top:8px;font-size:11px;color:#999;">
      <span>Rules: <b style="color:#ccc">${ruleScore}</b></span>
      <span>AI: <b style="color:#ccc">${aiScore >= 0 ? aiScore : "—"}</b></span>
      <span>Final: <b style="color:${c.text}">${score}</b></span>
    </div>`;

    overlayEl.innerHTML = `
      <div style="
        position:fixed;
        top:12px;
        right:12px;
        z-index:2147483647;
        width:340px;
        background:#1a1a2e;
        border:2px solid ${c.border};
        border-radius:14px;
        padding:16px;
        box-shadow:0 8px 32px rgba(0,0,0,0.5);
        font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
        color:#e0e0e0;
        animation:phd-slideIn 0.3s ease;
      ">
        <style>
          @keyframes phd-slideIn {
            from { transform:translateX(120%); opacity:0; }
            to { transform:translateX(0); opacity:1; }
          }
        </style>

        <!-- Close button -->
        <div id="phd-close" style="
          position:absolute;top:8px;right:12px;
          cursor:pointer;font-size:18px;color:#666;
          line-height:1;
        ">&times;</div>

        <!-- Header -->
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div style="
            width:44px;height:44px;border-radius:50%;
            border:3px solid ${c.border};
            display:flex;align-items:center;justify-content:center;
            font-size:20px;font-weight:bold;color:${c.text};
            box-shadow:0 0 12px ${c.border}33;
          ">${score}</div>
          <div>
            <div style="font-size:16px;font-weight:bold;color:${c.text};">${status}</div>
            <div style="font-size:11px;color:#888;">Phishing Detector</div>
          </div>
        </div>

        ${scoreBreakdown}
        ${aiLine}
      </div>
    `;

    document.body.appendChild(overlayEl);

    // Close button
    overlayEl.querySelector("#phd-close").addEventListener("click", removeOverlay);

    // Auto-dismiss after 12 seconds for safe emails
    if (status === "Safe") {
      setTimeout(removeOverlay, 12000);
    }
  }

  function showScanningOverlay() {
    removeOverlay();
    overlayEl = document.createElement("div");
    overlayEl.id = "phishing-detector-overlay";
    overlayEl.innerHTML = `
      <div style="
        position:fixed;
        top:12px;
        right:12px;
        z-index:2147483647;
        width:280px;
        background:#1a1a2e;
        border:2px solid #6c63ff;
        border-radius:14px;
        padding:16px;
        box-shadow:0 8px 32px rgba(0,0,0,0.5);
        font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
        color:#e0e0e0;
        display:flex;align-items:center;gap:12px;
        animation:phd-slideIn 0.3s ease;
      ">
        <style>
          @keyframes phd-slideIn {
            from { transform:translateX(120%); opacity:0; }
            to { transform:translateX(0); opacity:1; }
          }
          @keyframes phd-spin {
            to { transform:rotate(360deg); }
          }
        </style>
        <div style="
          width:28px;height:28px;flex-shrink:0;
          border:3px solid #333;border-top:3px solid #6c63ff;
          border-radius:50%;
          animation:phd-spin 0.8s linear infinite;
        "></div>
        <div>
          <div style="font-size:13px;font-weight:600;">Scanning email...</div>
          <div style="font-size:11px;color:#888;">AI + rule-based analysis</div>
        </div>
      </div>
    `;
    document.body.appendChild(overlayEl);
  }

  // ============================================================
  // Auto-Scan Logic
  // ============================================================

  async function autoScan() {
    // Only analyze when a specific email is opened, never the inbox list
    if (!isEmailOpen()) {
      // If we were previously viewing an email and now we're back to inbox, clean up
      if (previouslyOpenEmail) {
        previouslyOpenEmail = false;
        removeOverlay();
      }
      return;
    }
    previouslyOpenEmail = true;

    const content = extractGmailContent();
    if (!content.text || content.text.length < 30) return;

    const now = Date.now();
    const textHash = content.text.substring(0, 300);
    const scanKey = getScanKey(content);

    if (scanInProgress && scanKey === activeScanKey) return;
    if (textHash === lastScannedText && now - lastCompletedScanAt < DUPLICATE_SCAN_WINDOW_MS) return;
    if (scanKey === lastCompletedScanKey && now - lastCompletedScanAt < DUPLICATE_SCAN_WINDOW_MS) return;
    if (scanKey === lastDisplayedScanKey && now - lastDisplayedScanAt < DUPLICATE_SCAN_WINDOW_MS) return;

    lastScannedText = textHash;
    scanInProgress = true;
    activeScanKey = scanKey;

    showScanningOverlay();

    try {
      const result = await fullAnalysis(content);
      lastCompletedScanKey = scanKey;
      lastCompletedScanAt = Date.now();

      if (result) {
        if (!(scanKey === lastDisplayedScanKey && Date.now() - lastDisplayedScanAt < DUPLICATE_SCAN_WINDOW_MS)) {
          showOverlay(result);
          lastDisplayedScanKey = scanKey;
          lastDisplayedScanAt = Date.now();
        }

        // Also store for popup to read
        chrome.storage.local.set({ lastResult: result, lastUrl: window.location.href });
      } else {
        removeOverlay();
      }
    } finally {
      scanInProgress = false;
      activeScanKey = "";
    }
  }

  // ============================================================
  // Watch for email opens (Gmail SPA navigation)
  // ============================================================

  function watchForEmailChanges() {
    let mutationTimer = null;

    // 1. MutationObserver — only trigger scan when email content appears
    const observer = new MutationObserver(() => {
      // Debounce rapid DOM mutations (Gmail renders in stages)
      if (mutationTimer) clearTimeout(mutationTimer);
      mutationTimer = setTimeout(() => {
        // Only schedule a scan if we're in an opened email view
        if (isEmailOpen()) {
          scheduleAutoScan(500);
        } else if (previouslyOpenEmail) {
          // Navigated away from email → clean up
          previouslyOpenEmail = false;
          removeOverlay();
        }
      }, 800);
    });

    const target = document.querySelector("[role='main']") || document.body;
    observer.observe(target, { childList: true, subtree: true });

    // 2. Hash change — Gmail navigates via hash (#inbox, #inbox/FMfcg...)
    let lastHash = window.location.hash;
    setInterval(() => {
      const currentHash = window.location.hash;
      if (currentHash !== lastHash) {
        lastHash = currentHash;
        // Reset so we can scan the new email
        lastScannedText = "";

        if (isEmailOpen()) {
          // Wait for Gmail to render the email content
          scheduleAutoScan(2500);
        } else {
          // Navigated to inbox/list view — remove overlay, do NOT scan
          previouslyOpenEmail = false;
          removeOverlay();
        }
      }
    }, 1000);
  }

  // ============================================================
  // Listen for messages from popup
  // ============================================================

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "EXTRACT_CONTENT") {
      const content = extractGmailContent();
      sendResponse(content);
      return true;
    }
    if (msg.action === "AUTO_SCAN") {
      scheduleAutoScan(500);
    }
  });

  // Listen for storage changes — react when user toggles auto-detect
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.autoDetect && changes.autoDetect.newValue === true) {
      // Just turned ON — scan current email immediately
      lastScannedText = "";
      lastCompletedScanKey = "";
      lastDisplayedScanKey = "";
      scheduleAutoScan(500);
    }
    if (changes.autoDetect && changes.autoDetect.newValue === false) {
      removeOverlay();
    }
  });

  // Start watching
  if (window.location.hostname.includes("mail")) {
    watchForEmailChanges();
    // Only scan on initial load if an email is already open (e.g., direct link)
    if (isEmailOpen()) {
      scheduleAutoScan(3000);
    }
  }
})();
