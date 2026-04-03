// ============================================================
// Warning Page Logic — extracted from inline script for MV3 CSP
// ============================================================

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('target');
const reason = params.get('reason');

// Display the blocked URL
if (targetUrl) {
  document.getElementById('url-display').textContent = targetUrl;
} else {
  document.getElementById('url-display').textContent = "Unknown URL";
}

// Customize title/description based on block reason
if (reason === 'unregistered') {
  document.getElementById('warning-title').textContent = "Dead Domain Blocked";
  document.getElementById('warning-desc').textContent =
    "PhishGuard intercepted this request. This domain is unregistered or offline, typical of 'burn-and-run' phishing campaigns.";
}

if (reason === 'dom_threat') {
  document.getElementById('warning-title').textContent = "Dangerous Page Content";
  document.getElementById('warning-desc').textContent =
    "PhishGuard detected dangerous elements on this page, such as password fields on an unencrypted connection or cross-origin data exfiltration attempts.";
}

if (reason === 'http') {
  document.getElementById('warning-title').textContent = "Insecure Site Blocked (HTTP)";
  document.getElementById('warning-desc').textContent =
    "PhishGuard blocked this site because it uses an unencrypted HTTP connection. Your data, passwords, and personal information can be intercepted by attackers on this site.";
}

// "Back to Safety" button
document.getElementById('back-btn').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
});

// "Ignore & Proceed" button
document.getElementById('proceed-btn').addEventListener('click', () => {
  if (!targetUrl) return;

  if (reason === 'unregistered') {
    alert("Cannot proceed: This domain does not exist on the internet.");
    return;
  }

  // Build the bypass URL so background.js skips re-interception
  let finalUrl;
  try {
    const bypassUrl = new URL(targetUrl);
    bypassUrl.searchParams.set('phishguard_bypass', 'true');
    finalUrl = bypassUrl.toString();
  } catch (e) {
    const separator = targetUrl.includes('?') ? '&' : '?';
    finalUrl = targetUrl + separator + 'phishguard_bypass=true';
  }

  // Send message to background script to navigate this tab.
  // chrome.tabs API is NOT available on extension pages loaded via
  // web_accessible_resources, so we ask the background service worker
  // (which has full chrome.tabs access) to do the navigation for us.
  chrome.runtime.sendMessage({
    action: "BYPASS_NAVIGATE",
    url: finalUrl
  }, () => {
    // If messaging fails (e.g., service worker not ready), fallback
    if (chrome.runtime.lastError) {
      window.location.href = finalUrl;
    }
  });
});
