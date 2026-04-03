// ============================================================
// DOM Threat Scanner — detects dangerous page content
// ============================================================

function scanDOMForThreats() {
  // Skip trusted sites entirely — no false positives on Gmail, Outlook, etc.
  const trustedSites = [
    'google.com', 'gmail.com', 'youtube.com',
    'microsoft.com', 'outlook.com', 'live.com', 'office.com', 'office365.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazonaws.com',
    'facebook.com', 'instagram.com', 'meta.com',
    'twitter.com', 'x.com',
    'github.com', 'linkedin.com',
    'paypal.com', 'stripe.com',
    'netflix.com', 'spotify.com',
    'dropbox.com', 'adobe.com',
    'notion.so', 'slack.com', 'zoom.us',
  ];

  const currentHost = window.location.hostname.toLowerCase();
  const isTrustedSite = trustedSites.some(d => currentHost === d || currentHost.endsWith('.' + d));
  if (isTrustedSite) return;

  const isHttp = window.location.protocol === 'http:';
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const forms = document.querySelectorAll('form');

  let threatDetected = false;
  let threatReason = "";

  // Threat 1: Password field on unencrypted connection
  if (isHttp && passwordFields.length > 0) {
    threatDetected = true;
    threatReason = "Unencrypted Password Field";
  }

  // Threat 2: Cross-origin form POST (data exfiltration)
  // Compare base domains (last 2 parts) instead of exact hostnames
  function getBaseDomain(hostname) {
    const parts = hostname.toLowerCase().split('.');
    return parts.slice(-2).join('.');
  }

  const currentBase = getBaseDomain(currentHost);

  forms.forEach(form => {
    if (threatDetected) return;
    const actionUrl = form.getAttribute('action');
    if (actionUrl && actionUrl.startsWith('http')) {
      try {
        const actionHost = new URL(actionUrl).hostname.toLowerCase();
        const actionBase = getBaseDomain(actionHost);

        // Only flag if the base domains are completely different
        if (actionBase !== currentBase) {
          // Also skip if action goes to a trusted domain
          const actionTrusted = trustedSites.some(d => actionHost === d || actionHost.endsWith('.' + d));
          if (!actionTrusted) {
            threatDetected = true;
            threatReason = "Data Exfiltration Risk (Cross-Origin Form)";
          }
        }
      } catch (e) {}
    }
  });

  if (threatDetected) {
    chrome.runtime.sendMessage({
      action: "DOM_THREAT_FOUND",
      reason: threatReason,
      url: window.location.href
    });
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scanDOMForThreats);
} else {
  scanDOMForThreats();
}

// ============================================================
// In-Page Link Click Interceptor with Warning Modal
// ============================================================

(() => {
  let blockedUrl = null;
  let isBypassing = false;
  let modalEl = null;

  // --- Trusted domains (skip interception) ---
  const safeDomains = [
    'google.com', 'gmail.com', 'youtube.com',
    'microsoft.com', 'outlook.com', 'live.com', 'office.com', 'office365.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazonaws.com',
    'facebook.com', 'instagram.com', 'meta.com',
    'twitter.com', 'x.com',
    'github.com', 'linkedin.com',
    'paypal.com', 'stripe.com',
    'netflix.com', 'spotify.com',
    'dropbox.com', 'adobe.com',
    'notion.so', 'slack.com', 'zoom.us',
  ];

  function isDomainSafe(hostname) {
    const h = hostname.toLowerCase();
    return safeDomains.some(d => h === d || h.endsWith('.' + d));
  }

  function isLinkSuspicious(url) {
    try {
      const parsed = new URL(url);

      // Safe protocols
      if (['chrome:', 'chrome-extension:', 'about:', 'data:', 'file:', 'mailto:', 'tel:', 'javascript:'].includes(parsed.protocol)) return false;
      if (['localhost', '127.0.0.1'].includes(parsed.hostname)) return false;

      // Trusted domains pass through
      if (isDomainSafe(parsed.hostname)) return false;

      // Already bypassed
      if (url.includes('phishguard_bypass=true')) return false;

      const domain = parsed.hostname.toLowerCase();
      let riskPts = 0;

      // HTTP = instant flag
      if (parsed.protocol === 'http:') riskPts += 40;

      // IP address as domain
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) riskPts += 50;

      // Suspicious TLDs
      if (/\.(xyz|top|click|loan|work|gq|ml|cf|tk|buzz|rest|support|icu|cam|surf|zip|mov)$/i.test(domain)) riskPts += 40;

      // Gibberish in domain (5+ consonants in a row)
      if (/[bcdfghjklmnpqrstvwxyz]{5,}/.test(domain)) riskPts += 40;

      // Brand spoofing
      const brands = ['paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon', 'facebook', 'chase', 'instagram', 'whatsapp'];
      brands.forEach(brand => {
        if (domain.includes(brand) && domain !== `${brand}.com` && !domain.endsWith(`.${brand}.com`)) {
          riskPts += 40;
        }
      });

      // Too many hyphens or subdomains
      if ((domain.match(/-/g) || []).length >= 2) riskPts += 20;
      if (domain.split('.').length > 4) riskPts += 30;

      // @ in URL (hidden redirect)
      if (url.includes('@') && !url.includes('mailto:')) riskPts += 40;

      // URL shorteners
      if (/^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|shorturl\.at|is\.gd|v\.gd|ow\.ly|buff\.ly|adf\.ly|tiny\.cc)$/i.test(domain)) riskPts += 40;

      return riskPts >= 40;
    } catch {
      return false;
    }
  }

  function removeModal() {
    if (modalEl) {
      modalEl.remove();
      modalEl = null;
    }
  }

  function showWarningModal(url) {
    removeModal();
    blockedUrl = url;

    modalEl = document.createElement('div');
    modalEl.id = 'phishguard-link-modal';
    modalEl.innerHTML = `
      <div style="
        position:fixed; top:0; left:0; width:100%; height:100%;
        background:rgba(0,0,0,0.7); z-index:2147483647;
        display:flex; align-items:center; justify-content:center;
        font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
        animation:pgm-fadeIn 0.2s ease;
      ">
        <style>
          @keyframes pgm-fadeIn { from{opacity:0} to{opacity:1} }
          @keyframes pgm-slideUp { from{transform:translateY(20px);opacity:0} to{transform:translateY(0);opacity:1} }
        </style>
        <div style="
          background:#1a1a2e; border:2px solid #ff4757; border-radius:16px;
          padding:32px 36px; max-width:480px; width:90%;
          text-align:center; color:#e0e0e0;
          box-shadow:0 8px 40px rgba(255,71,87,0.3);
          animation:pgm-slideUp 0.3s ease;
        ">
          <div style="
            width:60px;height:60px;border-radius:50%;
            border:3px solid #ff4757; margin:0 auto 16px;
            display:flex;align-items:center;justify-content:center;
            font-size:28px; background:rgba(255,71,87,0.1);
            box-shadow:0 0 20px rgba(255,71,87,0.3);
          ">&#9888;</div>
          <div style="font-size:20px;font-weight:700;color:#ff4757;margin-bottom:8px;">
            Suspicious Link Detected
          </div>
          <div style="font-size:14px;color:rgba(255,255,255,0.6);margin-bottom:16px;line-height:1.5;">
            PhishGuard flagged this link as potentially dangerous. It may lead to a phishing or malicious site.
          </div>
          <div style="
            background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.06);
            border-radius:10px; padding:12px; font-family:monospace;
            font-size:12px; color:#ffb347; word-break:break-all;
            margin-bottom:24px; max-height:60px; overflow:auto;
          ">${url}</div>
          <div style="display:flex;gap:12px;justify-content:center;">
            <button id="pgm-cancel-btn" style="
              background:#00e5a0; color:#06080d; border:none;
              padding:12px 24px; border-radius:10px;
              font-weight:700; font-size:14px; cursor:pointer;
              font-family:'Segoe UI',sans-serif;
              box-shadow:0 4px 16px rgba(0,229,160,0.3);
            ">Back to Safety</button>
            <button id="pgm-proceed-btn" style="
              background:transparent; color:rgba(255,255,255,0.4);
              border:1px solid rgba(255,255,255,0.1);
              padding:12px 24px; border-radius:10px;
              font-weight:600; font-size:14px; cursor:pointer;
              font-family:'Segoe UI',sans-serif;
            ">Proceed Anyway</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(modalEl);

    // Cancel — just close modal
    modalEl.querySelector('#pgm-cancel-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      removeModal();
      blockedUrl = null;
    });

    // Proceed — navigate to the blocked URL
    modalEl.querySelector('#pgm-proceed-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      removeModal();
      if (blockedUrl) {
        // Build bypass URL so background.js onBeforeNavigate also skips it
        let bypassUrl = blockedUrl;
        try {
          const parsed = new URL(blockedUrl);
          parsed.searchParams.set('phishguard_bypass', 'true');
          bypassUrl = parsed.toString();
        } catch {
          // Fallback: append manually
          const sep = blockedUrl.includes('?') ? '&' : '?';
          bypassUrl = blockedUrl + sep + 'phishguard_bypass=true';
        }

        const savedUrl = bypassUrl;
        blockedUrl = null;

        // Set bypass flag for the content script click interceptor
        isBypassing = true;

        setTimeout(() => {
          window.location.href = savedUrl;
        }, 50);
      }
    });

    // Click outside modal = cancel
    modalEl.addEventListener('click', (e) => {
      if (e.target === modalEl.firstElementChild) {
        removeModal();
        blockedUrl = null;
      }
    });
  }

  // --- Event delegation: intercept all link clicks ---
  document.addEventListener('click', (event) => {
    // If we're in bypass mode, let the click through
    if (isBypassing) {
      isBypassing = false;
      return;
    }

    // Find the closest anchor element (handles nested elements like <a><span>text</span></a>)
    const link = event.target.closest('a');
    if (!link) return;

    const href = link.href;
    if (!href) return;

    // Check if this link is suspicious
    if (isLinkSuspicious(href)) {
      event.preventDefault();
      event.stopPropagation();
      showWarningModal(href);
    }
  }, true); // Use capture phase to intercept before other handlers
})();
