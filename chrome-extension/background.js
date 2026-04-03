// ============================================================
// Background Service Worker — Handles Gemini API calls + tab events
// + URL Blocking & DOM Threat Interception
// ============================================================

const GEMINI_API_KEY = "AIzaSyDdal7TH9wHjB5Vvqx2wmveSVJm4V-zFfs";
const GEMINI_MODEL = "gemini-2.5-flash-lite";

// --- Supabase Logging ---
const SUPABASE_URL = "https://zjfuosrpvpiswxmhfxpr.supabase.co/rest/v1/scans";
const SUPABASE_ANON_KEY = "sb_publishable_k0bXILKUSe-huuY8naCyAQ_oX8IQVV3";

async function logThreatToDatabase(url, score) {
  try {
    await fetch(SUPABASE_URL, {
      method: "POST",
      headers: {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": `Bearer ${SUPABASE_ANON_KEY}`,
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
      },
      body: JSON.stringify({
        input_text: `[EXTENSION BLOCKED] ${url}`,
        result: "Phishing",
        risk_score: score
      })
    });
  } catch (error) {
    console.error("Failed to log to Supabase:", error);
  }
}

// --- URL Danger Heuristics ---
async function isLinkDangerous(url) {
  try {
    const parsedUrl = new URL(url);

    // Allow safe internal protocols
    if (['chrome:', 'chrome-extension:', 'about:', 'data:', 'file:'].includes(parsedUrl.protocol)) return false;
    if (['localhost', '127.0.0.1'].includes(parsedUrl.hostname)) return false;

    const domain = parsedUrl.hostname.toLowerCase();
    const rawUrl = url.toLowerCase();

    // ===== INSTANT BLOCK: All HTTP sites =====
    if (parsedUrl.protocol === 'http:') return true;

    // ===== POINT-BASED CHECKS FOR HTTPS SITES =====
    let riskPts = 0;

    // Gibberish detector — 5+ consonants in a row
    if (/[bcdfghjklmnpqrstvwxyz]{5,}/.test(domain)) riskPts += 40;

    // Suspicious TLDs
    if (/\.(xyz|top|click|loan|work|gq|ml|cf|tk|buzz|rest|support|icu|cam|surf|zip|mov|nexus|foo|bar)$/i.test(domain)) riskPts += 40;

    // IP address as domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) riskPts += 50;

    // Semantic threat words in domain
    const threatWords = ['login', 'verify', 'update', 'secure', 'account', 'auth', 'billing', 'support', 'recover', 'signin', 'password', 'credential', 'banking', 'wallet'];
    let wordMatches = 0;
    threatWords.forEach(word => { if (domain.includes(word)) wordMatches++; });
    if (wordMatches >= 2) riskPts += 40;
    if (wordMatches === 1 && domain.includes('-')) riskPts += 25;

    // Brand spoofing detection
    const brands = ['paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon', 'facebook', 'chase', 'instagram', 'whatsapp', 'telegram', 'twitter', 'linkedin', 'dropbox', 'adobe', 'wellsfargo', 'citibank', 'bankofamerica'];
    brands.forEach(brand => {
      if (domain.includes(brand)) {
        const isLegitMain = domain === `${brand}.com`;
        const isLegitSubdomain = domain.endsWith(`.${brand}.com`);
        if (!isLegitMain && !isLegitSubdomain) riskPts += 40;
      }
    });

    // Too many hyphens (e.g., secure-login-paypal-verify.com)
    if ((domain.match(/-/g) || []).length >= 2) riskPts += 20;

    // Too many subdomains (e.g., login.secure.bank.evil.com)
    if (domain.split('.').length > 4) riskPts += 30;

    // Hidden destination (@ symbol in URL)
    if (rawUrl.includes("@") && !rawUrl.includes("mailto:")) riskPts += 40;

    // Very long URL (obfuscation)
    if (url.length > 300) riskPts += 25;

    // URL shorteners (instant block)
    if (/^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|shorturl\.at|is\.gd|v\.gd|ow\.ly|buff\.ly|adf\.ly|tiny\.cc|lnk\.to)$/i.test(domain)) riskPts += 40;

    // Punycode / IDN homograph attacks
    if (domain.startsWith('xn--')) riskPts += 40;

    return riskPts >= 40;
  } catch (e) {
    return true;
  }
}

// --- Intercept navigation to dangerous URLs ---
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const targetUrl = details.url;
  if (targetUrl.includes('phishguard_bypass=true')) return;

  // Skip safe protocols
  try {
    const proto = new URL(targetUrl).protocol;
    if (['chrome:', 'chrome-extension:', 'about:', 'data:', 'file:'].includes(proto)) return;
  } catch { return; }

  const isDangerous = await isLinkDangerous(targetUrl);
  if (isDangerous) {
    // Determine reason for warning page
    let reason = '';
    try {
      const p = new URL(targetUrl);
      if (p.protocol === 'http:') reason = 'http';
    } catch {}

    logThreatToDatabase(targetUrl, 85);
    const warningPageUrl = chrome.runtime.getURL(`warning.html?target=${encodeURIComponent(targetUrl)}${reason ? '&reason=' + reason : ''}`);
    chrome.tabs.update(details.tabId, { url: warningPageUrl });
  }
});

// --- Catch fake/dead URLs ---
chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0) return;

  const targetUrl = details.url;
  const fakeUrlErrors = ["net::ERR_NAME_NOT_RESOLVED", "net::ERR_CONNECTION_REFUSED", "net::ERR_NAME_RESOLUTION_FAILED"];

  if (fakeUrlErrors.includes(details.error)) {
    const warningPageUrl = chrome.runtime.getURL(`warning.html?target=${encodeURIComponent(targetUrl)}&reason=unregistered`);
    chrome.tabs.update(details.tabId, { url: warningPageUrl });
  }
});

function getAiDiagnostic(error) {
  const message = String(error?.message || "Unknown AI error");
  const status = Number(error?.status || 0);

  if (status === 403 && /(referer|referrer|origin|api key)/i.test(message)) {
    return "Gemini rejected this extension request. The API key likely only allows your web app origin, not chrome-extension:// requests.";
  }

  if (status === 400 && /api key not valid/i.test(message)) {
    return "The configured Gemini API key is invalid.";
  }

  if (status === 429) {
    return "Gemini rate limit reached. Try again in a moment.";
  }

  if (/failed to fetch|networkerror/i.test(message)) {
    return "The extension could not reach the Gemini API.";
  }

  return message;
}

function getCandidateText(candidate) {
  const parts = candidate?.content?.parts || [];
  return parts
    .map((part) => typeof part?.text === "string" ? part.text : "")
    .filter(Boolean)
    .join("\n")
    .trim();
}

function tryParseAiJson(rawText) {
  if (!rawText) return null;

  const cleaned = rawText
    .replace(/```json/gi, "```")
    .replace(/```/g, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {}

  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (!jsonMatch) return null;

  try {
    return JSON.parse(jsonMatch[0]);
  } catch {
    return null;
  }
}

function fallbackParseAiText(rawText) {
  if (!rawText) return null;

  const cleaned = rawText.replace(/\s+/g, " ").trim();
  const lowered = cleaned.toLowerCase();

  let status = null;
  if (/\bphishing\b/.test(lowered) && !/\bnot phishing\b/.test(lowered)) {
    status = "Phishing";
  } else if (/\bsuspicious\b/.test(lowered)) {
    status = "Suspicious";
  } else if (/\bsafe\b|\blegitimate\b/.test(lowered)) {
    status = "Safe";
  }

  if (!status) return null;

  const scoreMatch = cleaned.match(/\bscore\b[^0-9]{0,10}(\d{1,3})\b/i) || cleaned.match(/\b(\d{1,3})\s*\/\s*100\b/);
  const score = scoreMatch
    ? Number(scoreMatch[1])
    : status === "Phishing"
      ? 90
      : status === "Suspicious"
        ? 45
        : 10;

  const sentenceMatch = cleaned.match(/[^.!?]+[.!?]/);
  const reason = (sentenceMatch ? sentenceMatch[0] : cleaned).trim();

  return {
    score,
    status,
    reason,
  };
}

function normalizeAiVerdict(parsed) {
  return {
    score: Math.max(0, Math.min(100, Number(parsed?.score) || 0)),
    status: ["Safe", "Suspicious", "Phishing"].includes(parsed?.status) ? parsed.status : "Safe",
    reason: String(parsed?.reason || "No details provided."),
  };
}

function buildAiPayload(text, senderEmail, links, compactMode = false) {
  const safeText = String(text || "");
  const safeSender = senderEmail || "unknown";
  const linkList = links && links.length > 0
    ? "\nLinks:\n" + links.slice(0, compactMode ? 5 : 10).join("\n")
    : "";

  const prompt = compactMode
    ? `Classify this email as Safe, Suspicious, or Phishing.

Return ONLY valid JSON with exactly these fields:
{"score":0-100,"status":"Safe|Suspicious|Phishing","reason":"short reason under 12 words"}

Rules:
- Safe for legitimate transactional emails from trusted domains.
- Phishing only if it tries to trick the user into clicking malicious links, sharing credentials, or acting under false urgency.

Sender: ${safeSender}${linkList}
Email:
"""
${safeText.substring(0, 1200)}
"""`
    : `You are a phishing email detection expert. Analyze this email and determine if it is a phishing attempt or legitimate.

IMPORTANT CONTEXT:
- Legitimate transactional emails (order confirmations, shipping updates, receipts, etc.) from real companies are SAFE even if they mention payment, accounts, or have tracking links.
- Amazon order confirmations, shipping notifications, delivery updates are SAFE.
- Only flag as phishing if the email is trying to TRICK the user into giving up credentials, clicking malicious links, or taking urgent action under false pretenses.
- Consider the sender address: emails from official domains (e.g. @amazon.com, @google.com) with normal transactional content are legitimate.
- Look for RED FLAGS: mismatched sender domain, urgent threats, requests to "verify" credentials via link, links to suspicious domains, poor grammar.

Return ONLY a valid JSON object (no markdown, no code blocks):
{
  "score": <number 0-100, 0=safe, 100=phishing>,
  "status": "<Safe|Suspicious|Phishing>",
  "reason": "<one short sentence under 12 words>"
}

Sender: ${safeSender}
${linkList}

Email content:
"""
${safeText.substring(0, 2200)}
"""`;

  return {
    contents: [{
      parts: [{ text: prompt }],
    }],
    generationConfig: {
      temperature: compactMode ? 0 : 0.1,
      maxOutputTokens: compactMode ? 80 : 180,
      thinkingConfig: {
        thinkingBudget: 0,
      },
      responseMimeType: "application/json",
      responseSchema: {
        type: "OBJECT",
        properties: {
          score: { type: "NUMBER" },
          status: {
            type: "STRING",
            enum: ["Safe", "Suspicious", "Phishing"],
          },
          reason: { type: "STRING" },
        },
        required: ["score", "status", "reason"],
      },
    },
  };
}

async function requestAiVerdict(text, senderEmail, links, compactMode = false) {
  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildAiPayload(text, senderEmail, links, compactMode)),
    }
  );

  if (!response.ok) {
    const rawError = await response.text();
    let message = `API ${response.status}`;

    try {
      const parsedError = JSON.parse(rawError);
      message = parsedError.error?.message || message;
    } catch {
      if (rawError) message = rawError;
    }

    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  const data = await response.json();
  const candidate = data.candidates?.[0];
  const raw = getCandidateText(candidate);
  const parsed = tryParseAiJson(raw) || fallbackParseAiText(raw);

  return {
    data,
    candidate,
    raw,
    parsed,
  };
}

// Content scripts can't call external APIs (CORS), so they route through here
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.action === "AI_DETECT") {
    const { text, senderEmail, links } = msg;
    aiDetect(text, senderEmail, links).then(sendResponse);
    return true; // keep channel open for async response
  }

  // DOM threat detected by dom-scanner content script
  if (msg.action === "DOM_THREAT_FOUND") {
    logThreatToDatabase(msg.url, 90);
    const warningPageUrl = chrome.runtime.getURL(`warning.html?target=${encodeURIComponent(msg.url)}&reason=dom_threat`);
    chrome.tabs.update(sender.tab.id, { url: warningPageUrl });
  }

  // Bypass navigation request from warning.html page
  if (msg.action === "BYPASS_NAVIGATE" && msg.url) {
    chrome.tabs.update(sender.tab.id, { url: msg.url });
  }

  return false;
});

// --- Fallback: Catch HTTP sites via tab URL changes ---
// Chrome's HTTPS-First mode can upgrade http:// to https:// before
// onBeforeNavigate fires. When HTTPS fails and Chrome falls back to HTTP,
// onBeforeNavigate may not re-fire. This catches the final committed URL.
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Check on URL change (catches redirects and fallbacks)
  if (changeInfo.url) {
    const url = changeInfo.url;
    if (url.includes('phishguard_bypass=true')) return;

    try {
      const parsed = new URL(url);
      if (['chrome:', 'chrome-extension:', 'about:', 'data:', 'file:'].includes(parsed.protocol)) return;
    } catch { return; }

    const isDangerous = await isLinkDangerous(url);
    if (isDangerous) {
      let reason = '';
      try {
        if (new URL(url).protocol === 'http:') reason = 'http';
      } catch {}

      logThreatToDatabase(url, 85);
      const warningPageUrl = chrome.runtime.getURL(`warning.html?target=${encodeURIComponent(url)}${reason ? '&reason=' + reason : ''}`);
      chrome.tabs.update(tabId, { url: warningPageUrl });
      return;
    }
  }

  // Auto-scan emails when tab finishes loading
  if (changeInfo.status !== "complete" || !tab.url) return;

  const isEmail = tab.url.includes("mail.google.com") ||
                  tab.url.includes("outlook.live.com") ||
                  tab.url.includes("outlook.office");

  if (!isEmail) return;

  chrome.storage.local.get({ autoDetect: false }, (prefs) => {
    if (prefs.autoDetect) {
      chrome.tabs.sendMessage(tabId, { action: "AUTO_SCAN" }).catch(() => {});
    }
  });
});

// ============================================================
// Gemini AI Detection
// ============================================================

async function aiDetect(text, senderEmail, links) {
  if (!GEMINI_API_KEY) {
    return {
      score: -1,
      status: "Unknown",
      reason: "AI unavailable",
      diagnostic: "No Gemini API key is configured for the extension.",
    };
  }

  try {
    let { data, candidate, raw, parsed } = await requestAiVerdict(text, senderEmail, links, false);

    const finishReason = candidate?.finishReason;
    const shouldRetryCompact = !parsed || finishReason === "MAX_TOKENS";

    if (shouldRetryCompact) {
      ({ data, candidate, raw, parsed } = await requestAiVerdict(text, senderEmail, links, true));
    }

    if (!parsed) {
      const blockReason = data.promptFeedback?.blockReason;
      const finalFinishReason = candidate?.finishReason;

      if (blockReason) {
        throw new Error(`Gemini blocked the prompt: ${blockReason}`);
      }

      if (finalFinishReason && finalFinishReason !== "STOP") {
        throw new Error(`Gemini returned no structured result (finishReason: ${finalFinishReason})`);
      }

      if (!raw) {
        throw new Error("Gemini returned an empty response");
      }

      throw new Error(`Could not parse Gemini response: ${raw.slice(0, 160)}`);
    }

    return normalizeAiVerdict(parsed);
  } catch (err) {
    const diagnostic = getAiDiagnostic(err);
    console.warn("AI detection failed:", diagnostic, err);
    return {
      score: -1,
      status: "Unknown",
      reason: "AI unavailable",
      diagnostic,
    };
  }
}
