import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
} from "recharts";
import { supabase } from "./supabaseClient";
import { jsPDF } from "jspdf";
import emailjs from "@emailjs/browser";
import ALL_TRAINING_QUESTIONS from "./trainingQuestions";

/* ═══════════════════════════════════════════════════════════════
   BUSINESS LOGIC
   ═══════════════════════════════════════════════════════════════ */

const PHISHING_SIGNALS = {
  urgentWords: /\b(urgent|immediately|suspend|verify|confirm|alert|warning|expire|locked|unauthorized|compromised|click here|act now|limited time)\b/gi,
  suspiciousDomains: /\b(bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|shorturl|0x[a-f0-9]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/gi,
  fakeAuth: /\b(password|ssn|social security|credit card|bank account|routing number|pin code|cvv|login credentials)\b/gi,
  spoofedBrands: /\b(paypal|apple|microsoft|google|amazon|netflix|facebook|instagram|whatsapp|chase|wells fargo|bank of america|citi)\b/gi,
  obfuscatedUrls: /(https?:\/\/[^\s]*@|https?:\/\/[^\s]*\d{5,}|xn--|%[0-9a-f]{2})/gi,
  threatPatterns: /\b(your account|dear customer|dear user|click below|update your|verify your|reset your|unusual activity|suspicious login|security update)\b/gi,
  grammarIssues: /\b(kindly|do the needful|revert back|same has been|please to)\b/gi,
};

const CHECK_DEFS = [
  { key: "urgentWords", label: "Urgency / pressure language", weight: 15, icon: "⚡" },
  { key: "suspiciousDomains", label: "Suspicious or shortened URLs", weight: 20, icon: "🔗" },
  { key: "fakeAuth", label: "Requests for sensitive data", weight: 22, icon: "🔑" },
  { key: "spoofedBrands", label: "Brand impersonation indicators", weight: 10, icon: "🎭" },
  { key: "obfuscatedUrls", label: "Obfuscated or deceptive links", weight: 25, icon: "🕸" },
  { key: "threatPatterns", label: "Common phishing templates", weight: 14, icon: "📋" },
  { key: "grammarIssues", label: "Suspicious grammar patterns", weight: 8, icon: "✏️" },
];

const TRUSTED_DOMAINS = [
  "google.com", "amazon.com", "microsoft.com", "paypal.com", "apple.com",
  "netflix.com", "facebook.com", "instagram.com", "github.com", "linkedin.com",
  "twitter.com", "x.com", "youtube.com", "dropbox.com", "adobe.com",
  "chase.com", "wellsfargo.com", "bankofamerica.com", "citi.com",
];

function extractDomains(text) {
  const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  return urls.map((u) => { try { return new URL(u).hostname; } catch { return null; } }).filter(Boolean);
}

function isTrustedDomain(hostname) {
  return TRUSTED_DOMAINS.some((td) => hostname === td || hostname.endsWith("." + td));
}

function computeHybridScore(ruleScore, aiScore, text) {
  const domains = extractDomains(text);
  const hasTrusted = domains.some(isTrustedDomain);
  const allTrusted = domains.length > 0 && domains.every(isTrustedDomain);

  // If AI is confident safe and domains are trusted, trust the AI
  if (aiScore < 20 && allTrusted) return { score: Math.min(aiScore, 15), adjusted: true };

  // Reduce rule score for trusted domains (brand names trigger spoofedBrands falsely)
  let adjustedRule = ruleScore;
  if (hasTrusted && ruleScore > 0) {
    adjustedRule = Math.max(0, Math.round(ruleScore * 0.4));
  }

  let finalScore;
  if (aiScore < 30) {
    // AI confident it's safe — lean heavily on AI
    finalScore = Math.round(adjustedRule * 0.25 + aiScore * 0.75);
  } else if (aiScore > 70) {
    // AI confident it's phishing — lean heavily on AI
    finalScore = Math.round(adjustedRule * 0.3 + aiScore * 0.7);
  } else {
    // Uncertain zone — weighted blend
    finalScore = Math.round(adjustedRule * 0.45 + aiScore * 0.55);
  }

  return { score: Math.min(Math.max(finalScore, 0), 100), adjusted: hasTrusted };
}

function analyzeContent(text) {
  if (!text.trim()) return null;
  const signals = [];
  let rawScore = 0;
  CHECK_DEFS.forEach(({ key, label, weight, icon }) => {
    const matches = text.match(PHISHING_SIGNALS[key]);
    if (matches && matches.length > 0) {
      const count = matches.length;
      const pts = Math.min(weight * Math.min(count, 4), weight * 2.5);
      rawScore += pts;
      signals.push({ label, count, severity: weight >= 20 ? "high" : weight >= 12 ? "medium" : "low", icon });
    }
  });
  const lower = text.toLowerCase();
  if (lower.includes("http") && !lower.includes("https://")) {
    rawScore += 10;
    signals.push({ label: "Non-HTTPS links detected", count: 1, severity: "medium", icon: "🔓" });
  }
  if ((text.match(/!/g) || []).length > 3) {
    rawScore += 5;
    signals.push({ label: "Excessive exclamation marks", count: (text.match(/!/g) || []).length, severity: "low", icon: "❗" });
  }
  const score = Math.min(Math.round(rawScore), 100);
  const status = score >= 65 ? "Phishing" : score >= 30 ? "Suspicious" : "Safe";
  return { score, status, signals };
}

function detectInputType(text) {
  const trimmed = text.trim();
  if (/^https?:\/\//i.test(trimmed) || /^[a-z0-9-]+(\.[a-z]{2,})+/i.test(trimmed)) {
    let urlStr = trimmed.split(/\s/)[0];
    if (!/^https?:\/\//i.test(urlStr)) urlStr = "http://" + urlStr;
    let domain = urlStr, isHttps = false;
    try { const parsed = new URL(urlStr); domain = parsed.hostname; isHttps = parsed.protocol === "https:"; } catch {}
    return { type: "URL", icon: "🔗", domain, isHttps };
  }
  if (/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i.test(trimmed)) return { type: "Email", icon: "📧", domain: null, isHttps: null };
  return { type: "Text", icon: "📝", domain: null, isHttps: null };
}

function analyzeUrl(rawUrl) {
  let urlStr = rawUrl.trim();
  if (!/^https?:\/\//i.test(urlStr)) urlStr = "http://" + urlStr;
  let parsed;
  try { parsed = new URL(urlStr); } catch { return null; }
  const domain = parsed.hostname;
  const protocol = parsed.protocol.replace(":", "");
  const path = parsed.pathname + parsed.search + parsed.hash;
  const parts = domain.split(".");
  const tld = parts.slice(-2).join(".");
  const subdomains = parts.length > 2 ? parts.slice(0, -2) : [];
  const findings = [];
  let riskPts = 0;
  if (protocol === "http") { findings.push({ label: "Insecure protocol (HTTP)", severity: "high", icon: "🔓" }); riskPts += 20; }
  if (rawUrl.includes("@")) { findings.push({ label: "Contains @ symbol — hides real destination", severity: "high", icon: "🎭" }); riskPts += 30; }
  if (/%[0-9a-f]{2}/i.test(rawUrl)) { findings.push({ label: "URL-encoded characters detected", severity: "high", icon: "🕸" }); riskPts += 25; }
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) { findings.push({ label: "IP address used instead of domain name", severity: "high", icon: "⚠" }); riskPts += 25; }
  if (/\d/.test(parts.slice(-2, -1)[0] || "")) { findings.push({ label: "Numbers in domain name — possible typosquat", severity: "medium", icon: "🔢" }); riskPts += 15; }
  if (subdomains.length >= 3) { findings.push({ label: `${subdomains.length} subdomains — abnormally deep`, severity: "medium", icon: "📎" }); riskPts += 15; }
  if (/^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|shorturl\.at|is\.gd|v\.gd)$/i.test(domain)) { findings.push({ label: "Known URL shortener — hides real destination", severity: "medium", icon: "🔗" }); riskPts += 20; }
  if (rawUrl.length > 120) { findings.push({ label: `Unusually long URL (${rawUrl.length} chars)`, severity: "low", icon: "📏" }); riskPts += 10; }
  if (/\.(xyz|top|click|loan|work|gq|ml|cf|tk|buzz|rest|support)$/i.test(domain)) { findings.push({ label: "Suspicious top-level domain", severity: "medium", icon: "🌐" }); riskPts += 15; }
  if ((domain.match(/-/g) || []).length >= 3) { findings.push({ label: "Excessive hyphens in domain — brand impersonation tactic", severity: "medium", icon: "➖" }); riskPts += 15; }
  const score = Math.min(riskPts, 100);
  const status = score >= 65 ? "Phishing" : score >= 30 ? "Suspicious" : "Safe";
  return { domain, protocol, tld, subdomains, path, score, status, findings, fullUrl: urlStr };
}

const ATTACK_TYPES = [
  { type: "Credential Harvesting", icon: "🔑", color: "#ff3366", keywords: /\b(password|login|credentials|sign.?in|username|verify your identity|confirm your account|authentication)\b/i },
  { type: "Fake Invoice", icon: "💳", color: "#ffb347", keywords: /\b(invoice|payment due|payment overdue|amount due|billing|outstanding balance|remittance|pay now)\b/i },
  { type: "CEO Fraud", icon: "👔", color: "#a78bfa", keywords: /\b(wire transfer|urgent favor|confidential|between us|process .* transfer|don't tell|ASAP|quick favor)\b/i },
  { type: "Delivery Scam", icon: "📦", color: "#4ade80", keywords: /\b(package|delivery|shipment|tracking|could not be delivered|reschedule|courier|parcel)\b/i },
  { type: "Password Reset Scam", icon: "🔐", color: "#38bdf8", keywords: /\b(reset your password|password reset|change your password|secure your account|recover your account)\b/i },
];

function detectAttackType(text) {
  for (const { type, icon, color, keywords } of ATTACK_TYPES) {
    if (keywords.test(text)) return { type, icon, color };
  }
  return { type: "General Phishing", icon: "🎣", color: "#f97316" };
}

const HIGHLIGHT_RULES = [
  { key: "urgentWords", color: "#ff3366", glow: "rgba(255,51,102,0.3)", label: "Urgency" },
  { key: "suspiciousDomains", color: "#ffb347", glow: "rgba(255,179,71,0.3)", label: "Suspicious URL" },
  { key: "fakeAuth", color: "#facc15", glow: "rgba(250,204,21,0.3)", label: "Sensitive Data" },
  { key: "spoofedBrands", color: "#a78bfa", glow: "rgba(167,139,250,0.3)", label: "Brand Spoof" },
  { key: "threatPatterns", color: "#f97316", glow: "rgba(249,115,22,0.3)", label: "Threat Pattern" },
  { key: "grammarIssues", color: "rgba(255,255,255,0.6)", glow: "rgba(255,255,255,0.15)", label: "Grammar" },
];

function highlightText(text) {
  const marks = [];
  HIGHLIGHT_RULES.forEach(({ key, color, glow }) => {
    const regex = new RegExp(PHISHING_SIGNALS[key].source, "gi");
    let m;
    while ((m = regex.exec(text)) !== null) marks.push({ start: m.index, end: m.index + m[0].length, color, glow });
  });
  if (marks.length === 0) return [text];
  marks.sort((a, b) => a.start - b.start || b.end - a.end);
  const filtered = [];
  let lastEnd = 0;
  for (const mark of marks) { if (mark.start >= lastEnd) { filtered.push(mark); lastEnd = mark.end; } }
  const parts = [];
  let cursor = 0;
  filtered.forEach((mark, i) => {
    if (mark.start > cursor) parts.push(text.slice(cursor, mark.start));
    parts.push(<span key={i} style={{ color: mark.color, fontWeight: 700, textShadow: `0 0 8px ${mark.glow}`, borderBottom: `2px solid ${mark.color}40`, paddingBottom: 1 }}>{text.slice(mark.start, mark.end)}</span>);
    cursor = mark.end;
  });
  if (cursor < text.length) parts.push(text.slice(cursor));
  return parts;
}

const GEMINI_API_KEY = process.env.REACT_APP_GEMINI_KEY;

async function aiDetect(text) {
  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ parts: [{ text: `Analyze the following text for phishing indicators. Return ONLY a valid JSON object with exactly these fields:\n- "score": number 0-100 (0=safe, 100=phishing)\n- "status": "Safe" or "Suspicious" or "Phishing"\n- "reason": one short sentence explaining why\n- "points": array of 2-4 short bullet point strings explaining key indicators found\n\nDo NOT wrap in markdown. Return raw JSON only.\n\nText:\n"""\n${text}\n"""` }] }], generationConfig: { temperature: 0.1, maxOutputTokens: 2048 } }),
    });
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    const data = await response.json();
    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON in response");
    const parsed = JSON.parse(jsonMatch[0]);
    return { score: Math.max(0, Math.min(100, Number(parsed.score) || 0)), status: ["Safe", "Suspicious", "Phishing"].includes(parsed.status) ? parsed.status : "Safe", reason: String(parsed.reason || "No explanation provided"), points: Array.isArray(parsed.points) ? parsed.points.map(String).slice(0, 5) : [] };
  } catch { return { score: 50, status: "Suspicious", reason: "AI unavailable", points: [] }; }
}

/* ═══════════════════════════════════════════════════════════════
   THEME SYSTEM (DARK ONLY)
   ═══════════════════════════════════════════════════════════════ */

const t = {
  bg: "#050508", bgAlt: "#0a0a12", panel: "rgba(10,12,22,0.75)", panelSolid: "#0c0e1a",
  panelBorder: "rgba(0,255,136,0.06)", panelBorderHover: "rgba(0,255,136,0.15)",
  accent: "#00ff88", accentDim: "rgba(0,255,136,0.08)", accentGlow: "rgba(0,255,136,0.25)",
  cyan: "#00d4ff", cyanDim: "rgba(0,212,255,0.08)", cyanGlow: "rgba(0,212,255,0.25)",
  purple: "#a78bfa", purpleDim: "rgba(167,139,250,0.08)",
  red: "#ff3366", redDim: "rgba(255,51,102,0.08)", redGlow: "rgba(255,51,102,0.25)",
  amber: "#ffb347", amberDim: "rgba(255,179,71,0.08)",
  text: "#e2e8f0", textMid: "rgba(255,255,255,0.55)", textDim: "rgba(255,255,255,0.3)", textFaint: "rgba(255,255,255,0.12)",
  inputBg: "rgba(0,0,0,0.45)", codeBg: "rgba(0,0,0,0.5)",
};

/* ═══════════════════════════════════════════════════════════════
   DIGITAL THREAT GRID (CLEAN, NO RAIN, PERFORMANCE OPTIMIZED)
   ═══════════════════════════════════════════════════════════════ */

function CyberBackground({ mousePos }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: false });
    
    let w, h;
    let animationFrameId;
    
    // --- 3D Grid & Nodes Setup ---
    const fov = 800;
    const camZ = -800;
    let camX = 0;
    let camY = -300;
    let targetCamX = 0;
    let targetCamY = -300;
    
    const gridSize = 150;
    const gridZMax = 5000;
    const gridXExtents = 4000;
    
    const nodes = [];
    const connections = [];
    const pulses = [];
    let waveZ = gridZMax;
    const waveSpeed = 15;
    const colors = [t.accent, t.cyan, t.purple];

    function init() {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
      
      // 1. Initialize Nodes
      nodes.length = 0;
      for (let i = 0; i < 120; i++) {
        const x = Math.round(((Math.random() - 0.5) * gridXExtents * 2) / gridSize) * gridSize;
        const z = Math.round((Math.random() * gridZMax) / gridSize) * gridSize;
        nodes.push({
          x, y: 0, z,
          baseRadius: 1.5 + Math.random() * 2,
          color: colors[Math.floor(Math.random() * colors.length)],
          pulsePhase: Math.random() * Math.PI * 2,
          pulseSpeed: 0.02 + Math.random() * 0.04,
        });
      }

      // 2. Initialize Connections
      connections.length = 0;
      nodes.forEach((n1, i) => {
        nodes.slice(i + 1).forEach(n2 => {
          const dist = Math.hypot(n1.x - n2.x, n1.z - n2.z);
          if (dist > 0 && dist <= gridSize * 2.5 && Math.random() > 0.6) {
            connections.push({
              n1, n2, opacity: 0, targetOpacity: Math.random() > 0.5 ? 0.3 : 0, timer: Math.random() * 200,
            });
          }
        });
      });
    }

    const project = (x, y, z) => {
      const dist = z - camZ;
      if (dist <= 0) return null;
      const scale = fov / dist;
      const px = w / 2 + (x - camX) * scale;
      const py = h / 2 + (y - camY) * scale;
      return { x: px, y: py, scale };
    };

    function draw() {
      // Background Clear
      ctx.fillStyle = "#020617";
      ctx.fillRect(0, 0, w, h);

      // --- Update Camera Parallax ---
      let mx = window.innerWidth / 2;
      let my = window.innerHeight / 2;
      if (mousePos && mousePos.current) {
        mx = mousePos.current.x;
        my = mousePos.current.y;
      }
      targetCamX = (mx - window.innerWidth / 2) * 1.5;
      targetCamY = -300 + (my - window.innerHeight / 2) * 0.5;
      camX += (targetCamX - camX) * 0.05;
      camY += (targetCamY - camY) * 0.05;

      // Update Scan Wave
      waveZ -= waveSpeed;
      if (waveZ < 0) waveZ = gridZMax;

      ctx.globalCompositeOperation = "screen";

      // --- 1. Draw Grid ---
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = -gridXExtents; x <= gridXExtents; x += gridSize) {
        const p1 = project(x, 0, 0);
        const p2 = project(x, 0, gridZMax);
        if (p1 && p2) { ctx.moveTo(p1.x, p1.y); ctx.lineTo(p2.x, p2.y); }
      }
      for (let z = 0; z <= gridZMax; z += gridSize) {
        const p1 = project(-gridXExtents, 0, z);
        const p2 = project(gridXExtents, 0, z);
        if (p1 && p2) { ctx.moveTo(p1.x, p1.y); ctx.lineTo(p2.x, p2.y); }
      }
      ctx.strokeStyle = "rgba(0, 150, 255, 0.15)";
      ctx.stroke();

      // --- 2. Draw Scan Wave ---
      const waveP1 = project(-gridXExtents, 0, waveZ);
      const waveP2 = project(gridXExtents, 0, waveZ);
      if (waveP1 && waveP2) {
        ctx.beginPath();
        ctx.moveTo(waveP1.x, waveP1.y);
        ctx.lineTo(waveP2.x, waveP2.y);
        ctx.strokeStyle = "rgba(0, 255, 136, 0.8)";
        
        // Use fake glow here to avoid expensive shadowBlur 
        ctx.lineWidth = 4;
        ctx.stroke();
        ctx.lineWidth = 1.5;
        ctx.strokeStyle = "#ffffff";
        ctx.stroke();
      }

      // --- 3. Draw Connections ---
      connections.forEach(c => {
        c.timer -= 1;
        if (c.timer <= 0) {
          c.targetOpacity = Math.random() > 0.6 ? 0.3 + Math.random() * 0.4 : 0;
          c.timer = 50 + Math.random() * 200;
        }
        c.opacity += (c.targetOpacity - c.opacity) * 0.05;

        if (c.opacity > 0.01) {
          const p1 = project(c.n1.x, c.n1.y, c.n1.z);
          const p2 = project(c.n2.x, c.n2.y, c.n2.z);
          if (p1 && p2) {
            const depthFade = Math.max(0, 1 - (c.n1.z + c.n2.z) / 2 / gridZMax);
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(0, 212, 255, ${c.opacity * depthFade})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      });

      // --- 4. Data Pulses ---
      if (Math.random() < 0.15 && connections.length > 0) {
        const activeConns = connections.filter(c => c.opacity > 0.1);
        if (activeConns.length > 0) {
          const conn = activeConns[Math.floor(Math.random() * activeConns.length)];
          pulses.push({
            conn, progress: 0, speed: 0.01 + Math.random() * 0.02, direction: Math.random() > 0.5 ? 1 : -1
          });
        }
      }

      for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i];
        p.progress += p.speed;
        if (p.progress >= 1) { pulses.splice(i, 1); continue; }

        const tt = p.direction === 1 ? p.progress : 1 - p.progress;
        const curX = p.conn.n1.x + (p.conn.n2.x - p.conn.n1.x) * tt;
        const curZ = p.conn.n1.z + (p.conn.n2.z - p.conn.n1.z) * tt;
        const projP = project(curX, 0, curZ);

        if (projP) {
          ctx.beginPath();
          ctx.arc(projP.x, projP.y, 2 * projP.scale, 0, Math.PI * 2);
          ctx.fillStyle = "#ffffff";
          ctx.fill();
          ctx.beginPath();
          ctx.arc(projP.x, projP.y, 6 * projP.scale, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0, 212, 255, 0.4)`;
          ctx.fill();
        }
      }

      // --- 5. Draw Nodes (Hardware Optimized) ---
      nodes.forEach(node => {
        node.pulsePhase += node.pulseSpeed;
        const p = project(node.x, node.y, node.z);
        if (!p) return;

        const depthFade = Math.max(0, 1 - node.z / gridZMax);
        const waveDist = Math.abs(node.z - waveZ);
        const waveGlow = Math.max(0, 1 - waveDist / 300);
        
        const pulseAnim = Math.sin(node.pulsePhase) * 0.5 + 0.5;
        const currentRadius = (node.baseRadius + pulseAnim + waveGlow * 3) * p.scale;

        // FAKE GLOW (Extremely fast compared to shadowBlur, stops scrolling lag)
        ctx.beginPath();
        ctx.arc(p.x, p.y, currentRadius * 3, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.globalAlpha = depthFade * (0.08 + waveGlow * 0.15);
        ctx.fill();

        // CORE NODE
        ctx.beginPath();
        ctx.arc(p.x, p.y, currentRadius, 0, Math.PI * 2);
        ctx.globalAlpha = depthFade * (0.5 + waveGlow * 0.5 + pulseAnim * 0.5);
        ctx.fill();
        
        ctx.globalAlpha = 1; // Reset alpha
      });

      // --- 6. Distance Fog ---
      ctx.globalCompositeOperation = "source-over";
      const fogGrad = ctx.createLinearGradient(0, 0, 0, h * 0.6);
      fogGrad.addColorStop(0, "#020617");
      fogGrad.addColorStop(1, "rgba(2, 6, 23, 0)");
      ctx.fillStyle = fogGrad;
      ctx.fillRect(0, 0, w, h * 0.6);

      animationFrameId = requestAnimationFrame(draw);
    }

    init();
    animationFrameId = requestAnimationFrame(draw);

    window.addEventListener("resize", init);

    return () => {
      window.removeEventListener("resize", init);
      cancelAnimationFrame(animationFrameId);
    };
  }, [mousePos]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: "fixed", top: 0, left: 0, width: "100%", height: "100%",
        zIndex: 0, pointerEvents: "none", background: "#020617",
        transform: "translateZ(0)", // GPU Acceleration for lag-free scroll
        willChange: "transform"
      }}
    />
  );
}

/* ═══════════════════════════════════════════════════════════════
   REUSABLE COMPONENTS
   ═══════════════════════════════════════════════════════════════ */

function GlassCard({ children, style, className = "", glow, onClick }) {
  return (
    <div onClick={onClick} className={`glass-card ${className}`} style={{
      backdropFilter: "blur(24px) saturate(1.2)", WebkitBackdropFilter: "blur(24px) saturate(1.2)",
      borderRadius: 18, overflow: "hidden", position: "relative",
      boxShadow: glow ? `0 0 40px ${glow}, 0 4px 24px rgba(0,0,0,0.2)` : "0 4px 24px rgba(0,0,0,0.15), 0 0 0 1px rgba(255,255,255,0.02)",
      ...style,
    }}>
      {children}
    </div>
  );
}

function ScoreRing({ score, status }) {
  const [anim, setAnim] = useState(0);
  const radius = 72, stroke = 5;
  const circ = 2 * Math.PI * radius;
  const offset = circ - (anim / 100) * circ;
  const color = status === "Phishing" ? t.red : status === "Suspicious" ? t.amber : t.accent;
  useEffect(() => {
    let frame, start = null;
    function run(ts) {
      if (!start) start = ts;
      const p = Math.min((ts - start) / 1200, 1);
      setAnim(Math.round(score * (1 - Math.pow(1 - p, 3))));
      if (p < 1) frame = requestAnimationFrame(run);
    }
    frame = requestAnimationFrame(run);
    return () => cancelAnimationFrame(frame);
  }, [score]);
  return (
    <div style={{ position: "relative", width: 200, height: 200, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ position: "absolute", inset: -20, borderRadius: "50%", background: `radial-gradient(circle, ${color}0a 0%, transparent 65%)`, animation: "subtleBreathe 4s ease-in-out infinite" }} />
      <svg width="200" height="200" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="100" cy="100" r={radius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={stroke + 2} />
        {Array.from({ length: 48 }).map((_, i) => {
          const angle = (i / 48) * 2 * Math.PI - Math.PI / 2;
          const r1 = radius + 8, r2 = radius + (i % 6 === 0 ? 15 : 11);
          return (<line key={i} x1={100 + r1 * Math.cos(angle)} y1={100 + r1 * Math.sin(angle)}
            x2={100 + r2 * Math.cos(angle)} y2={100 + r2 * Math.sin(angle)}
            stroke={i / 48 <= anim / 100 ? `${color}70` : "rgba(255,255,255,0.06)"} strokeWidth={i % 6 === 0 ? 1.5 : 0.7} />);
        })}
        <circle cx="100" cy="100" r={radius} fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 14px ${color}90)`, transition: "stroke 0.5s" }} />
        {anim > 0 && (() => {
          const a = (anim / 100) * 2 * Math.PI - Math.PI / 2;
          return <circle cx={100 + radius * Math.cos(a)} cy={100 + radius * Math.sin(a)} r="5" fill={color} style={{ filter: `drop-shadow(0 0 10px ${color})` }} />;
        })()}
      </svg>
      <div style={{ position: "absolute", display: "flex", flexDirection: "column", alignItems: "center" }}>
        <span style={{ fontSize: 46, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1, letterSpacing: -2, textShadow: `0 0 20px ${color}40` }}>{anim}</span>
        <span style={{ fontSize: 8, color: t.textDim, letterSpacing: 4, textTransform: "uppercase", marginTop: 8, fontFamily: "'JetBrains Mono', monospace" }}>risk score</span>
      </div>
    </div>
  );
}

function RadarScanAnimation() {
  return (
    <div style={{ display: "flex", justifyContent: "center" }}>
      <svg viewBox="0 0 200 200" width="160" height="160">
        <circle cx="100" cy="100" r="80" fill="none" stroke={`${t.accent}15`} strokeWidth="0.8" />
        <circle cx="100" cy="100" r="55" fill="none" stroke={`${t.accent}10`} strokeWidth="0.8" />
        <circle cx="100" cy="100" r="30" fill="none" stroke={`${t.accent}08`} strokeWidth="0.8" />
        <line x1="100" y1="20" x2="100" y2="180" stroke={`${t.accent}06`} strokeWidth="0.5" />
        <line x1="20" y1="100" x2="180" y2="100" stroke={`${t.accent}06`} strokeWidth="0.5" />
        <g className="radar-sweep">
          <path d="M100,100 L100,20 A80,80 0 0,1 169,60 Z" fill={`url(#sweepG)`} />
        </g>
        <circle cx="100" cy="100" r="3" fill={t.accent} className="radar-dot-center" />
        <circle cx="130" cy="65" r="2" fill={t.red} className="radar-blip-1" />
        <circle cx="72" cy="130" r="2" fill={t.amber} className="radar-blip-2" />
        <circle cx="145" cy="115" r="1.5" fill={t.red} className="radar-blip-3" />
        <defs>
          <linearGradient id="sweepG" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={`${t.accent}40`} /><stop offset="100%" stopColor={`${t.accent}00`} />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

function StatCard({ label, value, icon, accentColor, total }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <GlassCard style={{ background: "rgba(10,12,22,0.8)", border: `1px solid ${t.panelBorder}`, padding: "22px 20px" }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${accentColor}80, ${accentColor}20, transparent)`, borderRadius: "18px 18px 0 0" }} />
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center",
          background: `${accentColor}10`, border: `1px solid ${accentColor}15`, fontSize: 18,
        }}>{icon}</div>
        {total > 0 && <span style={{ fontSize: 11, color: `${accentColor}`, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>{pct}%</span>}
      </div>
      <div style={{ fontSize: 34, fontWeight: 800, color: accentColor, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1, marginBottom: 8, letterSpacing: -1 }}>{value}</div>
      <div style={{ fontSize: 10, color: t.textDim, letterSpacing: 2, textTransform: "uppercase", fontFamily: "'JetBrains Mono', monospace", fontWeight: 500 }}>{label}</div>
      <div style={{ marginTop: 14, height: 3, borderRadius: 2, background: "rgba(255,255,255,0.05)" }}>
        <div style={{ height: "100%", borderRadius: 2, width: `${pct}%`, background: `linear-gradient(90deg, ${accentColor}80, ${accentColor}40)`, transition: "width 1s cubic-bezier(0.22,1,0.36,1)", boxShadow: `0 0 8px ${accentColor}30` }} />
      </div>
    </GlassCard>
  );
}

function SignalCard({ signal, index }) {
  const colors = {
    high: { bg: t.redDim, border: `${t.red}25`, text: t.red, bar: t.red },
    medium: { bg: t.amberDim, border: `${t.amber}25`, text: t.amber, bar: t.amber },
    low: { bg: t.textFaint, border: t.textFaint, text: t.textMid, bar: t.textDim },
  };
  const c = colors[signal.severity];
  return (
    <div className="signal-card" style={{
      background: c.bg, border: `1px solid ${c.border}`, borderRadius: 12,
      padding: "12px 16px", display: "flex", alignItems: "center", gap: 12,
      animationDelay: `${index * 80}ms`,
    }}>
      <span style={{ fontSize: 17, width: 26, textAlign: "center" }}>{signal.icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12.5, color: c.text, fontWeight: 600 }}>{signal.label}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
          <div style={{ flex: 1, height: 3, borderRadius: 2, background: t.textFaint }}>
            <div style={{ height: "100%", borderRadius: 2, background: c.bar, width: `${Math.min(signal.count * 25, 100)}%`, transition: "width 0.6s ease" }} />
          </div>
          <span style={{ fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>×{signal.count}</span>
        </div>
      </div>
      <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 1.5, color: c.text, padding: "3px 8px", borderRadius: 4, background: `${c.bar}12`, fontFamily: "'JetBrains Mono', monospace" }}>
        {signal.severity === "high" ? "HIGH" : signal.severity === "medium" ? "MED" : "LOW"}
      </span>
    </div>
  );
}

function HistoryRow({ scan, index }) {
  const [quarantined, setQuarantined] = useState(false);
  const color = scan.status === "Phishing" ? t.red : scan.status === "Suspicious" ? t.amber : t.accent;
  
  return (
    <div className="history-row" style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "12px 16px", borderRadius: 10,
      background: index % 2 === 0 ? `${t.textFaint}30` : "transparent",
    }}>
      <div style={{ flex: 1, minWidth: 0, marginRight: 16 }}>
        <div style={{ fontSize: 13, color: t.textMid, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 380 }}>{scan.preview}</div>
        <div style={{ fontSize: 10, marginTop: 3, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{new Date(scan.timestamp).toLocaleString()}</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {/* NEW: Enterprise Quarantine Button for Phishing/Suspicious links */}
        {(scan.status === "Phishing" || scan.status === "Suspicious") && (
          <button 
            onClick={() => setQuarantined(true)}
            disabled={quarantined}
            style={{
              padding: "4px 10px", borderRadius: 6, fontSize: 9, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", cursor: quarantined ? "default" : "pointer",
              background: quarantined ? `${t.accent}20` : "transparent",
              color: quarantined ? t.accent : t.textDim,
              border: `1px solid ${quarantined ? t.accent : t.textFaint}`,
              transition: "all 0.2s"
            }}>
            {quarantined ? "✓ QUARANTINED" : "BLOCK GLOBALLY"}
          </button>
        )}
        <div style={{ width: 48, height: 4, borderRadius: 2, background: t.textFaint }}>
          <div style={{ height: "100%", borderRadius: 2, background: color, width: `${scan.score}%` }} />
        </div>
        <span style={{ fontSize: 13, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace", minWidth: 24, textAlign: "right" }}>{scan.score}</span>
        <span style={{ fontSize: 9, padding: "4px 10px", borderRadius: 6, fontWeight: 700, background: `${color}12`, color, border: `1px solid ${color}25`, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}>{scan.status.toUpperCase()}</span>
      </div>
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: t.panelSolid, border: `1px solid ${t.panelBorder}`, borderRadius: 10, padding: "10px 14px", backdropFilter: "blur(10px)" }}>
      <div style={{ fontSize: 11, color: t.textDim, marginBottom: 4, fontFamily: "'JetBrains Mono', monospace" }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ fontSize: 13, color: p.color, fontWeight: 600 }}>{p.name}: {p.value}</div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MAIN APP
   ═══════════════════════════════════════════════════════════════ */

export default function PhishingDetector() {
  const mousePos = useRef(null);

  useEffect(() => {
    const handler = (e) => { mousePos.current = { x: e.clientX, y: e.clientY }; };
    window.addEventListener("mousemove", handler);
    return () => window.removeEventListener("mousemove", handler);
  }, []);

  const [page, setPage] = useState("scan");
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [history, setHistory] = useState([]);
  const [aiReason, setAiReason] = useState("");
  const [aiPoints, setAiPoints] = useState([]);
  const [demoQueued, setDemoQueued] = useState(false);
  const [showAllSignals, setShowAllSignals] = useState(false);
  const [engineDisagree, setEngineDisagree] = useState(false);
  const [ssEngineDisagree, setSsEngineDisagree] = useState(false);
  const textRef = useRef(null);
  const [sandboxSim, setSandboxSim] = useState(null);
  const [simEmail, setSimEmail] = useState("");
  const [simTemplate, setSimTemplate] = useState("credential");
  const [simulations, setSimulations] = useState([]);
  const [simSending, setSimSending] = useState(false);
  const [simError, setSimError] = useState("");
  const [simMode, setSimMode] = useState("website");

  // Screenshot scanner state
  const [ssImage, setSsImage] = useState(null);        // base64 data URL
  const [ssFile, setSsFile] = useState(null);           // File object for preview
  const [ssExtractedText, setSsExtractedText] = useState("");
  const [ssResult, setSsResult] = useState(null);
  const [ssAiReason, setSsAiReason] = useState("");
  const [ssAiPoints, setSsAiPoints] = useState([]);
  const [ssScanning, setSsScanning] = useState(false);
  const [ssScanStep, setSsScanStep] = useState(0);
  const [ssDragOver, setSsDragOver] = useState(false);
  const ssFileRef = useRef(null);

  const ssScanSteps = ["Reading image", "Extracting text via Gemini Vision", "Parsing content", "Analyzing language signals", "Running AI phishing detection", "Computing risk score"];

  const handleScreenshotFile = useCallback((file) => {
    if (!file || !file.type.startsWith("image/")) return;
    setSsResult(null); setSsExtractedText(""); setSsAiReason(""); setSsAiPoints([]);
    setSsFile(URL.createObjectURL(file));
    const reader = new FileReader();
    reader.onload = () => setSsImage(reader.result);
    reader.readAsDataURL(file);
  }, []);

  const pickRandomQuestions = useCallback((allQs, count = 10) => {
    const shuffled = [...allQs].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, count);
  }, []);

  const [TRAINING_QUESTIONS, setTrainingQuestions] = useState([]);
  useEffect(() => { if (TRAINING_QUESTIONS.length === 0) setTrainingQuestions(pickRandomQuestions(ALL_TRAINING_QUESTIONS, 10)); }, []);

  const [tqIndex, setTqIndex] = useState(0);
  const [tScore, setTScore] = useState(0);
  const [tStreak, setTStreak] = useState(0);
  const [tBestStreak, setTBestStreak] = useState(0);
  const [tAnswered, setTAnswered] = useState(null);
  const [tFinished, setTFinished] = useState(false);
  const [tTimer, setTTimer] = useState(15);
  const tTimerRef = useRef(null);

  useEffect(() => {
    if (page !== "training" || tFinished || tAnswered) { clearInterval(tTimerRef.current); return; }
    setTTimer(15);
    tTimerRef.current = setInterval(() => {
      setTTimer((prev) => {
        if (prev <= 1) { clearInterval(tTimerRef.current); setTAnswered("timeout"); setTStreak(0); return 0; }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(tTimerRef.current);
  }, [page, tqIndex, tFinished, tAnswered]);

  const handleTrainingAnswer = useCallback((userAnswer) => {
    if (tAnswered) return;
    clearInterval(tTimerRef.current);
    const correct = userAnswer === TRAINING_QUESTIONS[tqIndex].answer;
    setTAnswered(correct ? "correct" : "wrong");
    if (correct) { setTScore((s) => s + 1); setTStreak((s) => { const next = s + 1; setTBestStreak((b) => Math.max(b, next)); return next; }); } else { setTStreak(0); }
  }, [tAnswered, tqIndex, TRAINING_QUESTIONS]);

  const handleTrainingNext = useCallback(() => {
    if (tqIndex + 1 >= TRAINING_QUESTIONS.length) setTFinished(true);
    else { setTqIndex((i) => i + 1); setTAnswered(null); }
  }, [tqIndex, TRAINING_QUESTIONS]);

  const handleTrainingRestart = useCallback(() => {
    setTrainingQuestions(pickRandomQuestions(ALL_TRAINING_QUESTIONS, 10));
    setTqIndex(0); setTScore(0); setTStreak(0); setTBestStreak(0); setTAnswered(null); setTFinished(false);
  }, [pickRandomQuestions]);

  useEffect(() => {
    (async () => {
      try {
        const { data: scansData, error: scansError } = await supabase.from("scans").select("*").order("created_at", { ascending: false }).limit(200);
        if (!scansError && scansData) setHistory(scansData.map((row) => ({ id: row.id, preview: (row.input_text || "").slice(0, 120), score: row.risk_score, status: row.result, signals: [], timestamp: row.created_at })));
      } catch {}
      try {
        const { data: simData, error: simErr } = await supabase.from("simulations").select("*").order("created_at", { ascending: false }).limit(100);
        if (!simErr && simData) setSimulations(simData.map((row) => ({ id: row.id, email: row.email, template: row.template_key || "", templateName: row.template_name || "", subject: row.subject || "", preview: row.message, icon: row.icon || "", status: row.clicked ? "Clicked" : "Not Clicked", sentAt: row.created_at })));
      } catch {}
    })();
  }, []);

  const saveHistory = useCallback(async (entry) => {
    try { await supabase.from("scans").insert({ input_text: entry.inputText, result: entry.status, risk_score: entry.score, created_at: entry.timestamp }); } catch {}
  }, []);

  const scanSteps = ["Parsing content", "Checking URL patterns", "Analyzing language signals", "Scanning brand spoofing", "Running AI analysis", "Computing risk score"];

  const handleScan = useCallback(() => {
    if (!input.trim()) return;
    setScanning(true); setResult(null); setAiReason(""); setAiPoints([]); setShowAllSignals(false); setEngineDisagree(false); setScanStep(0);
    const si = setInterval(() => setScanStep((p) => { if (p >= scanSteps.length - 1) { clearInterval(si); return p; } return p + 1; }), 320);
    setTimeout(async () => {
      clearInterval(si);
      const ruleRes = analyzeContent(input);
      let aiRes;
      try { aiRes = await aiDetect(input); } catch { aiRes = { score: 50, status: "Suspicious", reason: "AI unavailable", points: [] }; }
      const { score: finalScore } = computeHybridScore(ruleRes.score, aiRes.score, input);
      const finalStatus = finalScore >= 65 ? "Phishing" : finalScore >= 30 ? "Suspicious" : "Safe";
      const ruleStatus = ruleRes.score >= 65 ? "Phishing" : ruleRes.score >= 30 ? "Suspicious" : "Safe";
      setEngineDisagree(ruleStatus !== aiRes.status);
      const res = { score: finalScore, status: finalStatus, signals: ruleRes.signals };
      setResult(res); setAiReason(aiRes.reason); setAiPoints(aiRes.points || []);
      const timestamp = new Date().toISOString();
      const entry = { id: Date.now(), preview: input.slice(0, 120), score: res.score, status: res.status, signals: res.signals, timestamp };
      const updated = [entry, ...history].slice(0, 200);
      setHistory(updated); setScanning(false);
      await saveHistory({ inputText: input, status: res.status, score: res.score, timestamp });
    }, 1800);
  }, [input, history, saveHistory]);

  const DEMO_TEXT = "Dear user, your account is suspended. Click here to verify: http://bit.ly/fake-link. Failure to respond within 12 hours will result in permanent account closure. — Apple Support Team";

  useEffect(() => { if (demoQueued && input === DEMO_TEXT && !scanning) { setDemoQueued(false); handleScan(); } }, [demoQueued, input, scanning, handleScan]);

  const handleScreenshotScan = useCallback(async () => {
    if (!ssImage) return;
    setSsScanning(true); setSsResult(null); setSsExtractedText(""); setSsAiReason(""); setSsAiPoints([]); setSsEngineDisagree(false); setSsScanStep(0);
    const si = setInterval(() => setSsScanStep((p) => { if (p >= 5) { clearInterval(si); return p; } return p + 1; }), 500);
    try {
      const [meta, base64Data] = ssImage.split(",");
      const mimeMatch = meta.match(/data:(.*?);/);
      const mimeType = mimeMatch ? mimeMatch[1] : "image/png";
      const ocrResponse = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [
            { inlineData: { mimeType, data: base64Data } },
            { text: "Extract all visible text from this image. Return only plain text, nothing else." }
          ] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 4096 },
        }),
      });
      if (!ocrResponse.ok) throw new Error(`Gemini Vision API error: ${ocrResponse.status}`);
      const ocrData = await ocrResponse.json();
      const extractedText = ocrData.candidates?.[0]?.content?.parts?.[0]?.text || "";
      setSsExtractedText(extractedText);
      if (!extractedText.trim()) {
        clearInterval(si);
        setSsResult({ score: 0, status: "Safe", signals: [] });
        setSsAiReason("No text could be extracted from this image.");
        setSsScanning(false);
        return;
      }
      const ruleRes = analyzeContent(extractedText);
      let aiRes;
      try { aiRes = await aiDetect(extractedText); } catch { aiRes = { score: 50, status: "Suspicious", reason: "AI unavailable", points: [] }; }
      const { score: finalScore } = computeHybridScore(ruleRes.score, aiRes.score, extractedText);
      const finalStatus = finalScore >= 65 ? "Phishing" : finalScore >= 30 ? "Suspicious" : "Safe";
      const ruleStatus = ruleRes.score >= 65 ? "Phishing" : ruleRes.score >= 30 ? "Suspicious" : "Safe";
      setSsEngineDisagree(ruleStatus !== aiRes.status);
      const res = { score: finalScore, status: finalStatus, signals: ruleRes.signals };
      clearInterval(si); setSsScanStep(5);
      setSsResult(res); setSsAiReason(aiRes.reason); setSsAiPoints(aiRes.points || []);
      const timestamp = new Date().toISOString();
      const entry = { id: Date.now(), preview: `[Screenshot] ${extractedText.slice(0, 100)}`, score: res.score, status: res.status, signals: res.signals, timestamp };
      setHistory((prev) => [entry, ...prev].slice(0, 200));
      await saveHistory({ inputText: `[Screenshot OCR] ${extractedText}`, status: res.status, score: res.score, timestamp });
    } catch (err) {
      clearInterval(si);
      setSsResult({ score: 0, status: "Safe", signals: [] });
      setSsAiReason(`Error: ${err.message}`);
    }
    setSsScanning(false);
  }, [ssImage, saveHistory]);

  const handleClear = useCallback(async () => { setHistory([]); try { await supabase.from("scans").delete().not("created_at", "is", null); } catch {} }, []);

  const SIM_TEMPLATES = {
    tata_aia: { name: "TATA AIA Lapsed Policy", subject: "URGENT: Your TATA AIA Life Policy is about to Lapse!", preview: "Dear Policyholder, your grace period ends today. Pay your renewal premium immediately here or lose your maturity benefits and coverage.", html: `<div style="font-family: sans-serif; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;"><div style="background-color: #003366; color: white; padding: 20px; text-align: center;"><h2 style="margin: 0;">TATA AIA Life Insurance</h2></div><div style="padding: 24px;"><p>Dear Policyholder,</p><p><strong>URGENT: Your TATA AIA Life Policy grace period ends today.</strong></p><p>Please pay your renewal premium immediately to avoid losing your maturity benefits and coverage.</p><div style="text-align: center; margin: 30px 0;"><a href="{{SIMULATION_LINK}}" style="background-color: #fca311; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; display: inline-block;">Pay Premium Now</a></div><p style="font-size: 12px; color: #666; margin-top: 40px;">If we do not receive payment within 24 hours, your policy will be permanently lapsed.</p></div></div>`, icon: "🛡️" },
    credential: { name: "Credential Harvest", subject: "Urgent: Verify Your Account", preview: "Your account has been flagged for unusual activity. Please verify your identity by clicking the link below and entering your login credentials.", icon: "🔑" },
    invoice: { name: "Fake Invoice", subject: "Invoice #INV-38291 — Payment Overdue", preview: "Please find attached your overdue invoice. Payment is required within 24 hours to avoid service disruption. Click here to pay now.", icon: "💳" },
    ceo: { name: "CEO Fraud", subject: "Quick Favor — Confidential", preview: "Hey, I need you to process a wire transfer urgently. I'm in a meeting and can't call. Please handle this ASAP and keep it between us.", icon: "👔" },
    delivery: { name: "Package Delivery", subject: "Your Package Could Not Be Delivered", preview: "We attempted to deliver your package but were unable to. Please confirm your address and reschedule delivery by clicking the link below.", icon: "📦" },
    password: { name: "Password Reset", subject: "Password Reset Request", preview: "We received a request to reset your password. If you did not make this request, click here to secure your account immediately.", icon: "🔐" },
  };

  const saveSimulations = useCallback(async (entry) => {
    try {
      const { data, error } = await supabase.from("simulations").insert({ email: entry.email, clicked: entry.status === "Clicked", created_at: entry.sentAt }).select().single();
      if (error) { console.warn("Supabase insert error:", error.message); return { id: Date.now() }; }
      return data;
    } catch (err) { console.error(err); return { id: Date.now() }; }
  }, []);

  const handleSendSimulation = useCallback(async () => {
    setSimError("");
    if (!simEmail.trim() || !simEmail.includes("@")) return;
    if (simMode === "email") {
      const now = Date.now();
      const globallyRecent = simulations.filter(s => Math.abs(now - new Date(s.sentAt).getTime()) < 60 * 1000);
      if (globallyRecent.length >= 5) { setSimError("Rate Limit Active: Sending too many simulations too fast. Please wait 60 seconds."); return; }
    }
    setSimSending(true);
    const template = SIM_TEMPLATES[simTemplate];
    const sentAt = new Date().toISOString();
    const entryData = { email: simEmail.trim(), template: simTemplate, templateName: template.name, subject: template.subject, preview: template.preview, icon: template.icon, status: "Not Clicked", sentAt, mode: simMode };
    const dbRecord = await saveSimulations(entryData);
    if (dbRecord) {
      if (simMode === "email") {
        const trackingLink = `${window.location.origin}/sandbox?id=${dbRecord.id}`;
        const rawHtml = template.html || `<div style="font-family: sans-serif; color: #333; padding: 20px; max-width: 600px; border: 1px solid #ddd; border-radius: 8px;"><p style="font-size: 15px; line-height: 1.6;">${template.preview}</p><div style="margin-top: 30px; text-align: center;"><a href="{{SIMULATION_LINK}}" style="background-color: #0056b3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">View Details</a></div></div>`;
        const finalHtml = rawHtml.replace("{{SIMULATION_LINK}}", trackingLink);
        try { await emailjs.send("service_lm4d94u", "template_van2ely", { to_email: simEmail.trim(), subject: template.subject, html_message: finalHtml, tracking_link: trackingLink }, "TY_p2ABlGQdmy5lqG"); } catch (err) { console.error("Failed to send email via EmailJS", err); }
      } else { await new Promise(r => setTimeout(r, 600)); }
      const entry = { id: dbRecord.id, ...entryData };
      setSimulations(prev => [entry, ...prev].slice(0, 100));
    }
    setSimEmail(""); setSimSending(false);
  }, [simEmail, simTemplate, simulations, saveSimulations, simMode]);

  const handleToggleSimStatus = useCallback(async (id) => {
    const sim = simulations.find((s) => s.id === id);
    if (!sim) return;
    const newClicked = sim.status !== "Clicked";
    setSimulations(prev => prev.map((s) => s.id === id ? { ...s, status: newClicked ? "Clicked" : "Not Clicked" } : s));
    try { await supabase.from("simulations").update({ clicked: newClicked }).eq("id", id); } catch {}
  }, [simulations]);

  const handleClearSimulations = useCallback(async () => { setSimulations([]); try { await supabase.from("simulations").delete().not("created_at", "is", null); } catch {} }, []);

  const displayedSims = useMemo(() => simulations.filter(sim => simMode === "email" ? sim.mode === "email" : sim.mode !== "email"), [simulations, simMode]);
  const simClickedCount = displayedSims.filter((s) => s.status === "Clicked").length;
  const simNotClickedCount = displayedSims.filter((s) => s.status === "Not Clicked").length;
  const totalScans = history.length;
  const phishingCount = history.filter((s) => s.status === "Phishing").length;
  const suspiciousCount = history.filter((s) => s.status === "Suspicious").length;
  const safeCount = history.filter((s) => s.status === "Safe").length;

  const activityData = useMemo(() => {
    const days = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      const label = d.toLocaleDateString("en", { month: "short", day: "numeric" });
      const ds = history.filter((s) => s.timestamp?.slice(0, 10) === key);
      days.push({ label, scans: ds.length, phishing: ds.filter((s) => s.status === "Phishing").length });
    }
    return days;
  }, [history]);

  const scoreDistribution = useMemo(() => {
    const b = [{ range: "0-20", count: 0 }, { range: "21-40", count: 0 }, { range: "41-60", count: 0 }, { range: "61-80", count: 0 }, { range: "81-100", count: 0 }];
    history.forEach((s) => { const i = s.score <= 20 ? 0 : s.score <= 40 ? 1 : s.score <= 60 ? 2 : s.score <= 80 ? 3 : 4; b[i].count++; });
    return b;
  }, [history]);

  const barColors = [t.accent, "#4ade80", t.amber, "#f97316", t.red];

  const statusColor = (s) => s === "Phishing" ? t.red : s === "Suspicious" ? t.amber : t.accent;

  const navTabs = [
    { key: "scan", label: "Scan", icon: "⌕" },
    { key: "dashboard", label: "Dashboard", icon: "◫" },
    { key: "simulation", label: "Simulation", icon: "◉" },
    { key: "training", label: "Training", icon: "◈" },
    { key: "screenshot", label: "Screenshot", icon: "◧" },
  ];

  const TAB_WIDTH = 105; // fixed width ensures perfect sliding mathematics

  return (
    <>
      <link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { overflow-x: hidden; }

        @keyframes fadeUp { from { opacity: 0; transform: translateY(20px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse-glow { 0%, 100% { opacity: 0.5; } 50% { opacity: 1; } }
        @keyframes sweep { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes blip1 { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
        @keyframes blip2 { 0%, 100% { opacity: 0.4; } 60% { opacity: 0.9; } }
        @keyframes blip3 { 0%, 100% { opacity: 0.2; } 40% { opacity: 0.8; } }
        @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
        @keyframes scanline { 0% { top: -10%; } 100% { top: 110%; } }
        @keyframes sending-pulse { 0%,100% { box-shadow: 0 0 0 0 ${t.purple}33; } 50% { box-shadow: 0 0 0 12px ${t.purple}00; } }
        @keyframes resultReveal { from { opacity: 0; transform: scale(0.95) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        @keyframes glowPulse { 0%, 100% { box-shadow: 0 0 20px rgba(0,255,136,0.1); } 50% { box-shadow: 0 0 40px rgba(0,255,136,0.2); } }
        @keyframes subtleBreathe { 0%, 100% { opacity: 0.7; } 50% { opacity: 1; } }
        @keyframes slideInModal { from { opacity: 0; transform: scale(0.92) translateY(20px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        @keyframes countUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

        .fade-up { animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) both; }
        .fade-up-d1 { animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) 0.07s both; }
        .fade-up-d2 { animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) 0.14s both; }
        .fade-up-d3 { animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) 0.21s both; }
        .fade-up-d4 { animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) 0.28s both; }
        .fade-in { animation: fadeIn 0.35s ease both; }
        .result-reveal { animation: resultReveal 0.6s cubic-bezier(0.22,1,0.36,1) both; }
        .modal-enter { animation: slideInModal 0.4s cubic-bezier(0.22,1,0.36,1) both; }

        /* Page transition wrapper */
        .page-transition { animation: fadeSlideIn 0.4s cubic-bezier(0.22,1,0.36,1) both; }

        .radar-sweep { transform-origin: 100px 100px; animation: sweep 2.5s linear infinite; }
        .radar-blip-1 { animation: blip1 2.5s ease-in-out infinite; }
        .radar-blip-2 { animation: blip2 2.5s ease-in-out 0.8s infinite; }
        .radar-blip-3 { animation: blip3 2.5s ease-in-out 1.6s infinite; }
        .radar-dot-center { animation: pulse-glow 2s ease-in-out infinite; }

        .glass-card {
          transition: transform 0.3s cubic-bezier(0.22,1,0.36,1), border-color 0.3s, box-shadow 0.4s;
          transform: translateZ(0);
          will-change: transform;
        }
        .glass-card:hover {
          border-color: ${t.panelBorderHover} !important;
          transform: translateY(-2px);
          box-shadow: 0 8px 32px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.03);
        }

        .signal-card { animation: fadeUp 0.4s cubic-bezier(0.22,1,0.36,1) both; transition: transform 0.2s, background 0.2s; }
        .signal-card:hover { transform: translateX(6px); }

        .history-row { transition: background 0.2s, transform 0.2s; }
        .history-row:hover { background: ${t.textFaint}50 !important; transform: translateX(2px); }

        .cyber-input {
          transition: border-color 0.3s, box-shadow 0.4s;
          font-family: 'JetBrains Mono', monospace;
        }
        .cyber-input:focus {
          outline: none;
          border-color: ${t.accent}50 !important;
          box-shadow: 0 0 0 4px ${t.accentDim}, 0 0 50px ${t.accentGlow}, inset 0 0 20px rgba(0,255,136,0.02);
        }
        .cyber-input::placeholder { color: ${t.textDim}; }

        .neon-btn {
          transition: all 0.25s cubic-bezier(0.22,1,0.36,1); position: relative; overflow: hidden;
          font-family: 'Sora', sans-serif;
        }
        .neon-btn:hover:not(:disabled) { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
        .neon-btn:active:not(:disabled) { transform: translateY(-1px); }
        .neon-btn:not(:disabled)::after {
          content: ''; position: absolute; inset: 0;
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent);
          background-size: 200% 100%; animation: shimmer 2.5s ease-in-out infinite;
        }

        .nav-tab-btn { transition: color 0.3s ease, text-shadow 0.3s; }
        .nav-tab-btn:hover { color: #ffffff !important; text-shadow: 0 0 12px rgba(255,255,255,0.15); }

        .sending-ring { animation: sending-pulse 1.2s ease-in-out infinite; }

        .template-card { transition: all 0.3s cubic-bezier(0.22,1,0.36,1); cursor: pointer; }
        .template-card:hover { background: ${t.textFaint}60 !important; transform: translateY(-3px); box-shadow: 0 8px 24px rgba(0,0,0,0.2); }
        .template-card.selected { border-color: ${t.accent}50 !important; background: ${t.accentDim} !important; box-shadow: 0 0 20px ${t.accentGlow}; }

        .sim-card {
          transition: transform 0.25s cubic-bezier(0.22,1,0.36,1), border-color 0.2s, box-shadow 0.3s;
          animation: fadeUp 0.45s cubic-bezier(0.22,1,0.36,1) both;
        }
        .sim-card:hover { transform: translateY(-3px); border-color: ${t.panelBorderHover} !important; box-shadow: 0 8px 24px rgba(0,0,0,0.25); }
        .stat-hover:hover { transform: translateY(-4px); border-color: ${t.panelBorderHover} !important; box-shadow: 0 8px 24px rgba(0,0,0,0.2); }

        .scan-step-bar { height: 2px; border-radius: 1px; background: ${t.accent}20; overflow: hidden; }
        .scan-step-fill { height: 100%; background: ${t.accent}; animation: step-check 0.3s ease-out forwards; }
        @keyframes step-check { from { width: 0; } to { width: 100%; } }

        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${t.textFaint}; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.15); }

        .recharts-cartesian-grid-horizontal line, .recharts-cartesian-grid-vertical line { stroke: ${t.textFaint}; }

        /* Noise overlay */
        .noise-overlay {
          position: fixed; inset: 0; z-index: 1; pointer-events: none;
          opacity: 0.018;
          background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='256' height='256' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E");
          background-repeat: repeat; background-size: 256px;
          transform: translateZ(0);
          will-change: transform;
        }

        /* Ambient gradient orbs behind content */
        .ambient-orb {
          position: fixed; border-radius: 50%; pointer-events: none; filter: blur(120px); z-index: 0;
          animation: subtleBreathe 8s ease-in-out infinite;
        }
      `}</style>

      <div style={{ fontFamily: "'Sora', 'Inter', sans-serif", background: t.bg, color: t.text, minHeight: "100vh", position: "relative" }}>
        <CyberBackground mousePos={mousePos} />
        <div className="noise-overlay" />
        {/* Ambient gradient orbs for depth */}
        <div className="ambient-orb" style={{ width: 600, height: 600, top: "10%", left: "-10%", background: `radial-gradient(circle, ${t.accent}08, transparent 70%)` }} />
        <div className="ambient-orb" style={{ width: 500, height: 500, top: "50%", right: "-10%", background: `radial-gradient(circle, ${t.purple}06, transparent 70%)`, animationDelay: "4s" }} />
        <div className="ambient-orb" style={{ width: 400, height: 400, bottom: "5%", left: "30%", background: `radial-gradient(circle, ${t.cyan}05, transparent 70%)`, animationDelay: "2s" }} />

        {/* ═══ NAV ═══ */}
        <nav className="relative z-10" style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "12px 32px", borderBottom: `1px solid ${t.panelBorder}`,
          background: "rgba(8,10,18,0.7)", backdropFilter: "blur(32px) saturate(1.3)", WebkitBackdropFilter: "blur(32px) saturate(1.3)",
          position: "sticky", top: 0, zIndex: 100,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center",
              background: `linear-gradient(135deg, ${t.accent}, #059669)`,
              boxShadow: `0 4px 20px ${t.accentGlow}, inset 0 1px 0 rgba(255,255,255,0.2)`,
            }}>
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <span style={{ fontSize: 17, fontWeight: 800, letterSpacing: -0.5, fontFamily: "'Sora', sans-serif" }}>PhishGuard</span>
            <span style={{
              fontSize: 8, padding: "3px 8px", borderRadius: 5, marginLeft: 2,
              background: `linear-gradient(135deg, ${t.accentDim}, rgba(0,255,136,0.15))`, color: t.accent, border: `1px solid ${t.accent}25`,
              fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, letterSpacing: 1.5,
            }}>PRO</span>
          </div>

          {/* Smooth Bubble Tabs Container */}
          <div style={{
            position: "absolute", left: "50%", transform: "translateX(-50%)",
            display: "flex", alignItems: "center", padding: 4, borderRadius: 14,
            background: "rgba(0,0,0,0.35)", border: `1px solid rgba(255,255,255,0.04)`,
            boxShadow: "inset 0 1px 3px rgba(0,0,0,0.3)",
          }}>
            {/* The Animated Bubble Background */}
            <div style={{
              position: "absolute",
              top: 4, bottom: 4, left: 4,
              width: TAB_WIDTH,
              background: `linear-gradient(135deg, ${t.accentDim}, rgba(0,255,136,0.12))`,
              borderRadius: 10,
              border: `1px solid ${t.accent}15`,
              transform: `translateX(${navTabs.findIndex(tb => tb.key === page) * TAB_WIDTH}px)`,
              transition: "transform 0.45s cubic-bezier(0.22, 1, 0.36, 1)",
              zIndex: 0,
              boxShadow: `0 0 16px ${t.accentGlow}`,
            }}>
              {/* Bottom Active Glow Line inside the moving bubble */}
              <div style={{
                position: "absolute", bottom: -4, left: "15%", right: "15%", height: 2,
                background: t.accent, borderRadius: 1, boxShadow: `0 0 12px ${t.accentGlow}, 0 0 4px ${t.accent}`
              }} />
            </div>

            {/* The Tab Buttons */}
            {navTabs.map((tab) => (
              <button key={tab.key} onClick={() => setPage(tab.key)} className="nav-tab-btn"
                style={{
                  width: TAB_WIDTH, padding: "8px 0", fontSize: 12.5, fontWeight: 600, border: "none", cursor: "pointer",
                  background: "transparent", position: "relative", zIndex: 1,
                  color: page === tab.key ? t.accent : t.textMid,
                  fontFamily: "'Sora', sans-serif",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  letterSpacing: 0.2,
                }}>
                <span style={{ marginRight: 6, fontSize: 13, opacity: page === tab.key ? 1 : 0.6, transition: "opacity 0.3s" }}>{tab.icon}</span>{tab.label}
              </button>
            ))}
          </div>

          {/* Version badge */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.accent, boxShadow: `0 0 8px ${t.accent}`, animation: "subtleBreathe 3s ease-in-out infinite" }} />
            <span style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1 }}>v2.0</span>
          </div>
        </nav>

        {/* ═══ SCAN PAGE ═══ */}
        {page === "scan" && (
          <div key="scan" className="relative z-10 page-transition" style={{ maxWidth: 760, margin: "0 auto", padding: "48px 24px 80px" }}>
            <div className="fade-up" style={{ textAlign: "center", marginBottom: 52 }}>
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 8,
                fontSize: 9, letterSpacing: 5, textTransform: "uppercase", color: t.accent,
                marginBottom: 18, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
                textShadow: `0 0 20px ${t.accentGlow}`,
                padding: "6px 16px", borderRadius: 20,
                background: `linear-gradient(135deg, ${t.accentDim}, rgba(0,255,136,0.04))`,
                border: `1px solid ${t.accent}15`,
              }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: t.accent, boxShadow: `0 0 6px ${t.accent}` }} />
                THREAT ANALYSIS ENGINE
              </div>
              <h1 style={{ fontSize: 42, fontWeight: 800, letterSpacing: -2, lineHeight: 1.1, fontFamily: "'Sora', sans-serif" }}>
                <span style={{
                  backgroundImage: `linear-gradient(135deg, ${t.accent}, ${t.cyan}, ${t.purple})`,
                  WebkitBackgroundClip: "text",
                  backgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  color: "transparent",
                }}>
                  Detect Phishing
                </span>
                <br />
                <span style={{ color: t.textMid, fontWeight: 300, fontSize: 28, letterSpacing: -0.5 }}>Before They Strike</span>
              </h1>
              <p style={{ marginTop: 14, fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 2.5 }}>
                HYBRID AI + RULE ENGINE  ·  REAL-TIME ANALYSIS  ·  7 DETECTION LAYERS
              </p>
            </div>

            <div className="fade-up-d1">
              <GlassCard style={{ background: "rgba(10,12,22,0.8)", border: `1px solid ${t.panelBorder}`, padding: 28 }}>
                {/* Input type indicator */}
                {input.trim() && (() => {
                  const info = detectInputType(input);
                  return (
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                      <span style={{ fontSize: 13 }}>{info.icon}</span>
                      <span style={{ fontSize: 9, color: t.cyan, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>DETECTED: {info.type.toUpperCase()}</span>
                    </div>
                  );
                })()}
                <div style={{ position: "relative" }}>
                  <div style={{ position: "absolute", top: 16, left: 18, fontSize: 14, color: t.textDim, pointerEvents: "none", zIndex: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                    {">"}_
                  </div>
                  <textarea ref={textRef} value={input} onChange={(e) => setInput(e.target.value)}
                    placeholder={'Paste email content or suspicious URL here…\n\nExample: "Dear Customer, Your account has been compromised.\nClick here to verify: http://bit.ly/x8k2m"'}
                    rows={7} className="cyber-input"
                    style={{
                      width: "100%", background: "rgba(0,0,0,0.5)", border: `1px solid ${t.panelBorder}`,
                      borderRadius: 14, padding: "16px 18px 16px 40px", color: t.text,
                      fontSize: 12.5, lineHeight: 1.8, resize: "vertical",
                    }} />
                </div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <span style={{ fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{input.length} chars</span>
                    {input.length > 0 && <span style={{ fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>· {input.split(/\s+/).filter(Boolean).length} words</span>}
                  </div>
                  <div style={{ display: "flex", gap: 10 }}>
                    <button onClick={() => { setInput(DEMO_TEXT); setDemoQueued(true); }} disabled={scanning}
                      className="neon-btn"
                      style={{
                        padding: "10px 18px", borderRadius: 11, fontSize: 12, fontWeight: 700, cursor: scanning ? "default" : "pointer",
                        background: scanning ? t.textFaint : `linear-gradient(135deg, ${t.purple}, #7c3aed)`,
                        border: "none", color: scanning ? t.textDim : "white",
                        boxShadow: scanning ? "none" : `0 4px 16px rgba(167,139,250,0.25)`,
                      }}>Demo</button>
                    {input && (
                      <button onClick={() => { setInput(""); setResult(null); }}
                        style={{ padding: "10px 18px", borderRadius: 11, fontSize: 12, fontWeight: 600, cursor: "pointer", background: "rgba(255,255,255,0.04)", border: `1px solid ${t.panelBorder}`, color: t.textMid, fontFamily: "'Sora', sans-serif", transition: "all 0.2s" }}>
                        Clear
                      </button>
                    )}
                    <button onClick={handleScan} disabled={!input.trim() || scanning} className="neon-btn"
                      style={{
                        padding: "10px 28px", borderRadius: 11, fontSize: 12.5, fontWeight: 700, border: "none",
                        cursor: !input.trim() || scanning ? "default" : "pointer",
                        background: !input.trim() || scanning ? t.textFaint : `linear-gradient(135deg, ${t.accent}, #059669)`,
                        color: !input.trim() || scanning ? t.textDim : "white",
                        boxShadow: !input.trim() || scanning ? "none" : `0 4px 24px ${t.accentGlow}, 0 0 0 1px rgba(0,255,136,0.15)`,
                        letterSpacing: 0.5,
                      }}>
                      {scanning ? "Analyzing…" : "⌕  Scan Now"}
                    </button>
                  </div>
                </div>
              </GlassCard>
            </div>

            {/* ═══ NEW: SLEEK WHY TRUST US SECTION ═══ */}
            {!scanning && !result && (
              <div className="fade-up-d2" style={{ marginTop: 42, padding: "0 12px" }}>
                
                <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 18 }}>
                  <div style={{ height: 1, flex: 1, background: `linear-gradient(90deg, transparent, ${t.panelBorder})` }} />
                  <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 3, fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", fontWeight: 600 }}>
                    Why Trust PhishGuard?
                  </span>
                  <div style={{ height: 1, flex: 1, background: `linear-gradient(-90deg, transparent, ${t.panelBorder})` }} />
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
                  {[
                    { icon: "🔒", title: "ZERO-TRUST", desc: "Links & scripts neutralized", color: t.accent },
                    { icon: "👁️", title: "STATELESS", desc: "Data never stored or sold", color: t.cyan },
                    { icon: "⚙️", title: "TRANSPARENT", desc: "No black-box decisions", color: t.purple }
                  ].map((feature, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <div style={{ fontSize: 16, filter: `drop-shadow(0 0 8px ${feature.color}40)` }}>{feature.icon}</div>
                      <div>
                        <div style={{ fontSize: 10, fontWeight: 800, color: feature.color, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}>{feature.title}</div>
                        <div style={{ fontSize: 10, color: t.textDim, marginTop: 2 }}>{feature.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>

              </div>
            )}
            {/* ═══ END OF SLEEK WHY TRUST US SECTION ═══ */}

            {scanning && (
              <div className="fade-in" style={{ marginTop: 32 }}>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "36px 28px", textAlign: "center" }}>
                  <RadarScanAnimation t={t} />
                  <p style={{ fontSize: 13, color: t.textMid, marginTop: 18, fontWeight: 600 }}>Analyzing threat vectors…</p>
                  <div style={{ marginTop: 20, maxWidth: 320, marginLeft: "auto", marginRight: "auto" }}>
                    {scanSteps.map((step, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 7, opacity: i <= scanStep ? 1 : 0.2, transition: "opacity 0.3s" }}>
                        <div style={{
                          width: 18, height: 18, borderRadius: 5, fontSize: 9, display: "flex", alignItems: "center", justifyContent: "center",
                          background: i <= scanStep ? t.accentDim : t.textFaint,
                          color: i <= scanStep ? t.accent : t.textDim, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
                          border: `1px solid ${i <= scanStep ? `${t.accent}30` : t.textFaint}`,
                        }}>{i < scanStep ? "✓" : i + 1}</div>
                        <span style={{ fontSize: 11, color: i <= scanStep ? t.textMid : t.textDim }}>{step}</span>
                        <div style={{ flex: 1 }}>{i <= scanStep && <div className="scan-step-bar"><div className="scan-step-fill" /></div>}</div>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              </div>
            )}

            {result && !scanning && (() => {
              const urls = input.match(/https?:\/\/[^\s]+/gi);
              if (!urls || urls.length === 0) return null;
              return (
                <div className="fade-up-d1" style={{ marginTop: 32 }}>
                  {urls.slice(0, 3).map((rawUrl, urlIdx) => {
                    const analysis = analyzeUrl(rawUrl);
                    if (!analysis) return null;
                    const urlColor = statusColor(analysis.status);
                    return (
                      <GlassCard key={urlIdx} style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "22px 24px", marginBottom: urlIdx < Math.min(urls.length, 3) - 1 ? 14 : 0 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div style={{ width: 6, height: 6, borderRadius: "50%", background: urlColor, boxShadow: `0 0 8px ${urlColor}` }} />
                            <span style={{ fontSize: 9, color: urlColor, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>URL SCANNER</span>
                          </div>
                          <span style={{ fontSize: 10, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: `${urlColor}10`, color: urlColor, border: `1px solid ${urlColor}25` }}>{analysis.score}/100</span>
                        </div>
                        <div style={{
                          padding: "12px 14px", borderRadius: 10, marginBottom: 16,
                          background: t.codeBg, border: `1px solid ${t.textFaint}`,
                          fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, lineHeight: 1.8,
                          wordBreak: "break-all", color: t.textDim,
                        }}>
                          <span style={{ color: analysis.protocol === "https" ? t.accent : t.red, fontWeight: 700 }}>{analysis.protocol}://</span>
                          {analysis.subdomains.length > 0 && <span style={{ color: t.amber }}>{analysis.subdomains.join(".")}<span style={{ color: t.textDim }}>.</span></span>}
                          <span style={{ color: t.text, fontWeight: 700 }}>{analysis.tld}</span>
                          {analysis.path && analysis.path !== "/" && <span style={{ color: t.textDim }}>{analysis.path}</span>}
                        </div>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
                          <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: t.purpleDim, color: t.purple, border: `1px solid ${t.purple}25` }}>{analysis.domain}</span>
                          <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: analysis.protocol === "https" ? t.accentDim : t.redDim, color: analysis.protocol === "https" ? t.accent : t.red, border: `1px solid ${analysis.protocol === "https" ? `${t.accent}30` : `${t.red}25`}` }}>{analysis.protocol.toUpperCase()}</span>
                          {analysis.subdomains.length > 0 && <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: t.amberDim, color: t.amber, border: `1px solid ${t.amber}25` }}>{analysis.subdomains.length} SUB{analysis.subdomains.length > 1 ? "S" : ""}</span>}
                          <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: `${urlColor}10`, color: urlColor, border: `1px solid ${urlColor}25` }}>{analysis.status.toUpperCase()}</span>
                        </div>
                        {analysis.findings.length > 0 && (
                          <div>
                            <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace", marginBottom: 10 }}>RISK INDICATORS — {analysis.findings.length} FOUND</div>
                            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                              {analysis.findings.map((f, fi) => {
                                const sc = f.severity === "high" ? { bg: t.redDim, border: `${t.red}25`, text: t.red } : f.severity === "medium" ? { bg: t.amberDim, border: `${t.amber}25`, text: t.amber } : { bg: t.textFaint, border: t.textFaint, text: t.textMid };
                                return (
                                  <div key={fi} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", borderRadius: 10, background: sc.bg, border: `1px solid ${sc.border}` }}>
                                    <span style={{ fontSize: 14, width: 22, textAlign: "center" }}>{f.icon}</span>
                                    <span style={{ flex: 1, fontSize: 11.5, color: sc.text, fontWeight: 600 }}>{f.label}</span>
                                    <span style={{ fontSize: 8, fontWeight: 700, letterSpacing: 1.5, padding: "2px 7px", borderRadius: 4, fontFamily: "'JetBrains Mono', monospace", color: sc.text, background: `${sc.text}12` }}>{f.severity.toUpperCase()}</span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                        {analysis.findings.length === 0 && <div style={{ textAlign: "center", padding: "10px 0" }}><span style={{ fontSize: 12, color: t.accent }}>No URL risk indicators detected</span></div>}
                      </GlassCard>
                    );
                  })}
                </div>
              );
            })()}

            {result && !scanning && (
              <div className="result-reveal" style={{ marginTop: 32 }}>
                <GlassCard style={{ background: "rgba(10,12,22,0.8)", border: `1px solid ${statusColor(result.status)}15`, padding: "36px 28px", boxShadow: `0 0 80px ${statusColor(result.status)}08, 0 8px 32px rgba(0,0,0,0.2)` }} glow={`${statusColor(result.status)}10`}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 32 }}>
                    <ScoreRing score={result.score} status={result.status} t={t} />
                    <div style={{ marginTop: 18, padding: "5px 18px", borderRadius: 8, fontSize: 12, fontWeight: 700, background: `${statusColor(result.status)}10`, color: statusColor(result.status), border: `1px solid ${statusColor(result.status)}20`, letterSpacing: 0.5, fontFamily: "'JetBrains Mono', monospace" }}>
                      {result.status === "Phishing" ? "⚠  PHISHING DETECTED" : result.status === "Suspicious" ? "△  SUSPICIOUS CONTENT" : "✓  APPEARS SAFE"}
                    </div>
                    {(() => {
                      const riskLevel = result.score >= 80 ? "CRITICAL" : result.score >= 60 ? "HIGH" : result.score >= 30 ? "MEDIUM" : "LOW";
                      const riskColor = result.score >= 80 ? t.red : result.score >= 60 ? "#f97316" : result.score >= 30 ? t.amber : t.accent;
                      const riskIcon = result.status === "Phishing" ? "🚨" : result.status === "Suspicious" ? "⚠️" : "✅";
                      const riskWord = result.status === "Phishing" ? "Dangerous" : result.status === "Suspicious" ? "Suspicious" : "Safe";
                      return (
                        <div style={{ marginTop: 14, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                          <div style={{ fontSize: 30 }}>{riskIcon}</div>
                          <div style={{ fontSize: 18, fontWeight: 800, color: riskColor }}>{riskWord}</div>
                          <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 3, color: riskColor, fontFamily: "'JetBrains Mono', monospace", padding: "3px 12px", borderRadius: 6, background: `${riskColor}10`, border: `1px solid ${riskColor}25` }}>{riskLevel}</span>
                        </div>
                      );
                    })()}
                  </div>

                  {(() => {
                    const inputInfo = detectInputType(input);
                    const riskLevel = result.score >= 65 ? "High" : result.score >= 30 ? "Medium" : "Low";
                    const riskColor = result.score >= 65 ? t.red : result.score >= 30 ? t.amber : t.accent;
                    return (
                      <div style={{ marginBottom: 24, padding: "14px 18px", borderRadius: 12, background: t.codeBg, border: `1px solid ${t.textFaint}`, display: "flex", flexWrap: "wrap", gap: 8 }}>
                        <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: t.cyanDim, color: t.cyan, border: `1px solid ${t.cyan}25` }}>{inputInfo.icon} INPUT: {inputInfo.type.toUpperCase()}</span>
                        <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: `${riskColor}10`, color: riskColor, border: `1px solid ${riskColor}25` }}>RISK: {riskLevel.toUpperCase()}</span>
                        {inputInfo.type === "URL" && inputInfo.domain && (
                          <>
                            <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: t.purpleDim, color: t.purple, border: `1px solid ${t.purple}25` }}>{inputInfo.domain}</span>
                            <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 6, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", background: inputInfo.isHttps ? t.accentDim : t.redDim, color: inputInfo.isHttps ? t.accent : t.red, border: `1px solid ${inputInfo.isHttps ? `${t.accent}30` : `${t.red}25`}` }}>{inputInfo.isHttps ? "HTTPS SECURE" : "HTTP INSECURE"}</span>
                          </>
                        )}
                      </div>
                    );
                  })()}

                  {engineDisagree && (
                    <div style={{ marginBottom: 20, padding: "12px 16px", borderRadius: 10, background: t.cyanDim, border: `1px solid ${t.cyan}20`, display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontSize: 16 }}>🔀</span>
                      <span style={{ fontSize: 11, color: t.cyan, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5 }}>
                        AI and heuristic engines disagree. Showing AI-preferred result for higher accuracy.
                      </span>
                    </div>
                  )}

                  <div style={{ marginBottom: 28 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 2 }}>THREAT LEVEL</span>
                      <span style={{ fontSize: 9, color: statusColor(result.status), fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>{result.score}/100</span>
                    </div>
                    <div style={{ height: 5, borderRadius: 3, background: t.textFaint, overflow: "hidden" }}>
                      <div style={{ height: "100%", borderRadius: 3, width: `${result.score}%`, backgroundImage: `linear-gradient(90deg, ${t.accent}, ${result.score > 30 ? t.amber : t.accent}, ${result.score > 65 ? t.red : t.amber})`, transition: "width 1.2s cubic-bezier(0.22,1,0.36,1)", boxShadow: `0 0 12px ${statusColor(result.status)}40` }} />
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
                      {["Safe", "Low", "Medium", "High", "Critical"].map((l) => <span key={l} style={{ fontSize: 8, color: t.textDim }}>{l}</span>)}
                    </div>
                  </div>

                  {result.status !== "Safe" && (() => {
                    const attack = detectAttackType(input);
                    return (
                      <div style={{ marginBottom: 24, padding: "14px 18px", borderRadius: 12, background: `${attack.color}08`, border: `1px solid ${attack.color}18`, display: "flex", alignItems: "center", gap: 12 }}>
                        <span style={{ fontSize: 22 }}>{attack.icon}</span>
                        <div>
                          <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace", marginBottom: 3 }}>ATTACK TYPE</div>
                          <div style={{ fontSize: 14, fontWeight: 700, color: attack.color }}>{attack.type}</div>
                        </div>
                      </div>
                    );
                  })()}

                  {result.signals.length > 0 ? (
                    <div>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                        <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>TOP SIGNALS — {result.signals.length} FOUND</span>
                        {result.signals.length > 3 && (
                          <button onClick={() => setShowAllSignals((p) => !p)} style={{ fontSize: 10, color: t.accent, background: "none", border: "none", cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, padding: 0 }}>
                            {showAllSignals ? "Show Top 3" : `Show All (${result.signals.length})`}
                          </button>
                        )}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                        {(showAllSignals ? result.signals : result.signals.slice(0, 3)).map((s, i) => <SignalCard key={i} signal={s} index={i} t={t} />)}
                      </div>
                    </div>
                  ) : (
                    <p style={{ textAlign: "center", fontSize: 13, color: t.textDim, padding: "18px 0" }}>No phishing indicators detected in this content.</p>
                  )}

                  {aiReason && (
                    <div style={{ marginTop: 22, padding: "18px 20px", borderRadius: 12, background: t.purpleDim, border: `1px solid ${t.purple}25` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.purple, boxShadow: `0 0 8px ${t.purple}` }} />
                        <span style={{ fontSize: 9, color: t.purple, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>AI ANALYSIS</span>
                      </div>
                      <p style={{ fontSize: 12, color: t.textMid, lineHeight: 1.7, margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>{aiReason}</p>
                      {aiPoints.length > 0 && (
                        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
                          {aiPoints.map((point, i) => (
                            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                              <span style={{ color: t.purple, fontSize: 12, lineHeight: "18px", flexShrink: 0 }}>▸</span>
                              <span style={{ fontSize: 11.5, color: t.textMid, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace" }}>{point}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  <div style={{ marginTop: 22, padding: "18px 20px", borderRadius: 12, background: t.accentDim, border: `1px solid ${t.accent}20` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.accent, boxShadow: `0 0 8px ${t.accent}` }} />
                      <span style={{ fontSize: 9, color: t.accent, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>RECOMMENDED ACTIONS</span>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {(result.status === "Phishing" ? ["Do not click any links in this message", "Do not reply or provide any personal information", "Change your password immediately if you already interacted", "Report this email to your IT security team", "Enable two-factor authentication on your accounts"] : result.status === "Suspicious" ? ["Verify the sender's email address carefully", "Do not click links — type URLs directly in your browser", "Contact the organization through official channels to confirm", "Enable two-factor authentication as a precaution"] : ["Content appears safe, but always stay vigilant", "Verify sender identity for any unexpected messages", "Keep your security software up to date"]).map((tip, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                          <span style={{ color: t.accent, fontSize: 12, lineHeight: "18px", flexShrink: 0 }}>▸</span>
                          <span style={{ fontSize: 11.5, color: t.textMid, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace" }}>{tip}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div style={{ marginTop: 20, display: "flex", justifyContent: "center", gap: 10 }}>
                    <button onClick={() => {
                      const text = `Phishing Detection Report\n------------------------\nStatus: ${result.status}\nScore: ${result.score}\nReason: ${aiReason}\n\nSignals:\n${result.signals.map(s => `- ${s.label} (x${s.count})`).join("\n")}\n\nAI Analysis Points:\n${aiPoints.map(p => `- ${p}`).join("\n") || "N/A"}\n`;
                      const blob = new Blob([text], { type: "text/plain" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "phishguard-report.txt"; a.click();
                    }} className="neon-btn" style={{ padding: "9px 20px", borderRadius: 10, fontSize: 11, fontWeight: 600, cursor: "pointer", background: t.textFaint, border: `1px solid ${t.panelBorder}`, color: t.textMid }}>Download TXT</button>
                    <button onClick={() => {
                      const doc = new jsPDF(); const pageW = doc.internal.pageSize.getWidth(); let y = 20;
                      const addLine = (text, size = 11, bold = false) => { doc.setFontSize(size); doc.setFont("helvetica", bold ? "bold" : "normal"); const lines = doc.splitTextToSize(text, pageW - 40); lines.forEach((line) => { if (y > 275) { doc.addPage(); y = 20; } doc.text(line, 20, y); y += size * 0.5 + 2; }); };
                      doc.setFontSize(20); doc.setFont("helvetica", "bold"); doc.text("PhishGuard - Detection Report", 20, y); y += 12;
                      doc.setDrawColor(0, 229, 160); doc.setLineWidth(0.5); doc.line(20, y, pageW - 20, y); y += 12;
                      addLine(`Generated: ${new Date().toLocaleString()}`, 9); y += 6;
                      addLine("RESULT SUMMARY", 13, true); y += 2;
                      addLine(`Status: ${result.status}`); addLine(`Risk Score: ${result.score} / 100`);
                      const riskLevel = result.score >= 80 ? "CRITICAL" : result.score >= 60 ? "HIGH" : result.score >= 30 ? "MEDIUM" : "LOW";
                      addLine(`Risk Level: ${riskLevel}`); y += 6;
                      if (aiReason) { addLine("AI ANALYSIS", 13, true); y += 2; addLine(`Reason: ${aiReason}`); if (aiPoints.length > 0) aiPoints.forEach((p) => addLine(`  - ${p}`)); y += 6; }
                      if (result.signals.length > 0) { addLine("DETECTED SIGNALS", 13, true); y += 2; result.signals.forEach((s) => addLine(`  [${s.severity.toUpperCase()}] ${s.label} (x${s.count})`)); y += 6; }
                      addLine("SCANNED CONTENT", 13, true); y += 2; addLine(input.slice(0, 2000), 9);
                      const pages = doc.internal.getNumberOfPages();
                      for (let i = 1; i <= pages; i++) { doc.setPage(i); doc.setFontSize(8); doc.setFont("helvetica", "normal"); doc.setTextColor(150); doc.text("PhishGuard Pro - Hybrid AI + Rule-Based Phishing Detection", 20, 290); doc.text(`Page ${i} of ${pages}`, pageW - 40, 290); doc.setTextColor(0); }
                      doc.save("phishguard-report.pdf");
                    }} className="neon-btn" style={{ padding: "9px 20px", borderRadius: 10, fontSize: 11, fontWeight: 600, cursor: "pointer", background: t.textFaint, border: `1px solid ${t.panelBorder}`, color: t.textMid }}>Download PDF</button>
                  </div>

                  <div style={{ marginTop: 14, textAlign: "center" }}>
                    <span style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1 }}>Hybrid AI + rule-based detection · Always verify sources manually</span>
                  </div>
                </GlassCard>
              </div>
            )}

            {result && !scanning && (
              <div className="fade-up-d3" style={{ marginTop: 24 }}>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "22px 24px" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.accent, boxShadow: `0 0 8px ${t.accent}` }} />
                      <span style={{ fontSize: 9, color: t.accent, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>HIGHLIGHTED ANALYSIS</span>
                    </div>
                    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                      {[{ label: "Urgency", color: "#ff3366" }, { label: "URLs", color: "#ffb347" }, { label: "Auth", color: "#facc15" }, { label: "Brands", color: "#a78bfa" }].map((leg) => (
                        <div key={leg.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                          <div style={{ width: 8, height: 3, borderRadius: 1, background: leg.color }} />
                          <span style={{ fontSize: 8, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{leg.label}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div style={{
                    padding: "16px 18px", borderRadius: 12, background: t.codeBg, border: `1px solid ${t.textFaint}`,
                    fontSize: 12, lineHeight: 2, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", whiteSpace: "pre-wrap", wordBreak: "break-word",
                  }}>{highlightText(input)}</div>
                </GlassCard>
              </div>
            )}
          </div>
        )}

        {/* ═══ DASHBOARD ═══ */}
        {page === "dashboard" && (
          <div key="dashboard" className="relative z-10 page-transition" style={{ maxWidth: 940, margin: "0 auto", padding: "44px 24px 80px" }}>
            <div className="fade-up" style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginBottom: 36 }}>
              <div>
                <div style={{
                  display: "inline-flex", alignItems: "center", gap: 8,
                  fontSize: 9, letterSpacing: 5, textTransform: "uppercase", color: t.accent,
                  marginBottom: 12, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
                  textShadow: `0 0 15px ${t.accentGlow}`,
                  padding: "5px 14px", borderRadius: 20,
                  background: `linear-gradient(135deg, ${t.accentDim}, rgba(0,255,136,0.04))`,
                  border: `1px solid ${t.accent}15`,
                }}>
                  <div style={{ width: 5, height: 5, borderRadius: "50%", background: t.accent, boxShadow: `0 0 6px ${t.accent}` }} />
                  ANALYTICS
                </div>
                <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: -1, fontFamily: "'Sora', sans-serif" }}>Threat Dashboard</h1>
              </div>
              {history.length > 0 && (
                <button onClick={handleClear} style={{ padding: "7px 14px", borderRadius: 8, fontSize: 10, fontWeight: 700, cursor: "pointer", background: t.redDim, border: `1px solid ${t.red}25`, color: t.red, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}>CLEAR ALL</button>
              )}
            </div>

            <div className="fade-up-d1" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 28 }}>
              <StatCard label="Total Scans" value={totalScans} icon="◎" accentColor={t.purple} total={totalScans} t={t} />
              <StatCard label="Phishing" value={phishingCount} icon="⚠" accentColor={t.red} total={totalScans} t={t} />
              <StatCard label="Suspicious" value={suspiciousCount} icon="△" accentColor={t.amber} total={totalScans} t={t} />
              <StatCard label="Safe" value={safeCount} icon="✓" accentColor={t.accent} total={totalScans} t={t} />
            </div>

            {totalScans > 0 && (
              <div className="fade-up-d2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 28 }}>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "22px 18px" }}>
                  <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, textTransform: "uppercase", marginBottom: 18, fontFamily: "'JetBrains Mono', monospace" }}>14-DAY ACTIVITY</div>
                  <ResponsiveContainer width="100%" height={180}>
                    <AreaChart data={activityData}>
                      <defs><linearGradient id="gradS" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.accent} stopOpacity={0.3} /><stop offset="100%" stopColor={t.accent} stopOpacity={0} /></linearGradient></defs>
                      <XAxis dataKey="label" tick={{ fontSize: 9, fill: t.textDim }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fontSize: 9, fill: t.textDim }} axisLine={false} tickLine={false} width={20} allowDecimals={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Area type="monotone" dataKey="scans" stroke={t.accent} strokeWidth={2} fill="url(#gradS)" name="Scans" dot={false} />
                      <Area type="monotone" dataKey="phishing" stroke={t.red} strokeWidth={1.5} fill="none" name="Phishing" dot={false} strokeDasharray="4 3" />
                    </AreaChart>
                  </ResponsiveContainer>
                </GlassCard>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "22px 18px" }}>
                  <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, textTransform: "uppercase", marginBottom: 18, fontFamily: "'JetBrains Mono', monospace" }}>SCORE DISTRIBUTION</div>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={scoreDistribution} barCategoryGap="25%">
                      <XAxis dataKey="range" tick={{ fontSize: 9, fill: t.textDim }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fontSize: 9, fill: t.textDim }} axisLine={false} tickLine={false} width={20} allowDecimals={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Bar dataKey="count" name="Scans" radius={[4, 4, 0, 0]}>{scoreDistribution.map((_, i) => <Cell key={i} fill={barColors[i]} fillOpacity={0.7} />)}</Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </GlassCard>
              </div>
            )}

            {totalScans > 0 && (
              <div className="fade-up-d3">
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "20px 24px", marginBottom: 28 }}>
                  <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, textTransform: "uppercase", marginBottom: 14, fontFamily: "'JetBrains Mono', monospace" }}>THREAT BREAKDOWN</div>
                  <div style={{ display: "flex", borderRadius: 5, overflow: "hidden", height: 10, background: t.textFaint }}>
                    {phishingCount > 0 && <div style={{ width: `${(phishingCount / totalScans) * 100}%`, background: t.red, transition: "width 0.8s ease" }} />}
                    {suspiciousCount > 0 && <div style={{ width: `${(suspiciousCount / totalScans) * 100}%`, background: t.amber, transition: "width 0.8s ease" }} />}
                    {safeCount > 0 && <div style={{ width: `${(safeCount / totalScans) * 100}%`, background: t.accent, transition: "width 0.8s ease" }} />}
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 12 }}>
                    {[{ label: "Phishing", count: phishingCount, color: t.red }, { label: "Suspicious", count: suspiciousCount, color: t.amber }, { label: "Safe", count: safeCount, color: t.accent }].map((item) => (
                      <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ width: 8, height: 8, borderRadius: 3, background: item.color }} />
                        <span style={{ fontSize: 12, color: t.textMid }}>{item.label}: <strong style={{ color: item.color }}>{totalScans > 0 ? Math.round((item.count / totalScans) * 100) : 0}%</strong></span>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              </div>
            )}

            <div className="fade-up-d4">
              <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, overflow: "hidden" }}>
                <div style={{ padding: "16px 24px", borderBottom: `1px solid ${t.panelBorder}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>RECENT SCANS</span>
                  <span style={{ fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{history.length} total</span>
                </div>
                {history.length === 0 ? (
                  <div style={{ padding: "56px 0", textAlign: "center" }}>
                    <div style={{ fontSize: 36, opacity: 0.08, marginBottom: 10 }}>◎</div>
                    <p style={{ fontSize: 12, color: t.textDim }}>No scans yet — go to the Scan tab to analyze content.</p>
                  </div>
                ) : (
                  <div style={{ padding: 12, display: "flex", flexDirection: "column", gap: 2 }}>
                    {history.slice(0, 25).map((scan, i) => <HistoryRow key={scan.id} scan={scan} index={i} t={t} />)}
                  </div>
                )}
              </GlassCard>
            </div>
          </div>
        )}

        {/* ═══ SIMULATION PAGE ═══ */}
        {page === "simulation" && (
          <div key="simulation" className="relative z-10 page-transition" style={{ maxWidth: 860, margin: "0 auto", padding: "44px 24px 80px" }}>
            <div className="fade-up" style={{ marginBottom: 36 }}>
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 8,
                fontSize: 9, letterSpacing: 5, textTransform: "uppercase",
                color: simMode === "email" ? t.purple : t.cyan,
                marginBottom: 12, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
                textShadow: `0 0 15px ${simMode === "email" ? t.purple : t.cyan}40`,
                padding: "5px 14px", borderRadius: 20,
                background: simMode === "email" ? `linear-gradient(135deg, ${t.purpleDim}, rgba(167,139,250,0.04))` : `linear-gradient(135deg, ${t.cyanDim}, rgba(0,212,255,0.04))`,
                border: `1px solid ${simMode === "email" ? t.purple : t.cyan}15`,
              }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: simMode === "email" ? t.purple : t.cyan, boxShadow: `0 0 6px ${simMode === "email" ? t.purple : t.cyan}` }} />
                {simMode === "email" ? "LIVE DISPATCHER" : "PHISHING SIMULATION"}
              </div>
              <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between" }}>
                <div>
                  <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: -1, fontFamily: "'Sora', sans-serif" }}>{simMode === "email" ? "Real Email Simulation" : "Simulation Lab"}</h1>
                  <p style={{ fontSize: 12, color: t.textMid, marginTop: 6, maxWidth: 450, lineHeight: 1.5 }}>
                    {simMode === "email" ? "Send actual phishing payloads to target email addresses with real tracking links." : "Send controlled phishing simulations to your dashboard to test employee awareness."}
                  </p>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                  {displayedSims.length > 0 && <button onClick={handleClearSimulations} style={{ padding: "8px 14px", borderRadius: 8, fontSize: 10, fontWeight: 700, cursor: "pointer", background: t.redDim, border: `1px solid ${t.red}25`, color: t.red, fontFamily: "'JetBrains Mono', monospace" }}>CLEAR ALL</button>}
                  {simMode === "email" ? (
                    <button onClick={() => setSimMode("website")} className="neon-btn" style={{ padding: "8px 18px", borderRadius: 8, fontSize: 11, fontWeight: 700, cursor: "pointer", background: t.textFaint, border: `1px solid ${t.panelBorder}`, color: t.textMid }}>← Back to Website Sim</button>
                  ) : (
                    <button onClick={() => setSimMode("email")} className="neon-btn" style={{ padding: "8px 18px", borderRadius: 8, fontSize: 11, fontWeight: 700, cursor: "pointer", background: `linear-gradient(135deg, ${t.purple}, #7c3aed)`, border: "none", color: "white", boxShadow: `0 4px 14px ${t.purple}40` }}>Try Real Sim 🚀</button>
                  )}
                </div>
              </div>
            </div>

            <div className="fade-up-d1">
              <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: 26, marginBottom: 24 }}>
                <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, textTransform: "uppercase", marginBottom: 16, fontFamily: "'JetBrains Mono', monospace" }}>
                  {simMode === "email" ? "DISPATCH REAL SIMULATION" : "NEW SIMULATION"}
                </div>

                {simError && (
                  <div className="fade-in" style={{ marginBottom: 18, padding: "11px 14px", borderRadius: 10, background: t.redDim, border: `1px solid ${t.red}30`, color: t.red, fontSize: 12, display: "flex", alignItems: "center", gap: 10, lineHeight: 1.5 }}>
                    <span style={{ fontSize: 16 }}>🛡️</span><span>{simError}</span>
                  </div>
                )}

                <div style={{ marginBottom: 18 }}>
                  <label style={{ display: "block", fontSize: 11, color: t.textMid, marginBottom: 7, fontWeight: 600 }}>Target Email Address</label>
                  <input type="email" value={simEmail} onChange={(e) => setSimEmail(e.target.value)} placeholder="employee@company.com" className="cyber-input"
                    style={{ width: "100%", background: t.inputBg, border: `1px solid ${t.panelBorder}`, borderRadius: 10, padding: "12px 16px", color: t.text, fontSize: 12 }} />
                </div>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: "block", fontSize: 11, color: t.textMid, marginBottom: 10, fontWeight: 600 }}>Simulation Template</label>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8 }}>
                    {Object.entries(SIM_TEMPLATES).map(([key, tmpl]) => (
                      <div key={key} className={`template-card ${simTemplate === key ? "selected" : ""}`} onClick={() => setSimTemplate(key)}
                        style={{ padding: "12px 8px", borderRadius: 12, textAlign: "center", background: simTemplate === key ? t.accentDim : t.textFaint, border: `1px solid ${simTemplate === key ? `${t.accent}40` : t.panelBorder}` }}>
                        <div style={{ fontSize: 20, marginBottom: 5 }}>{tmpl.icon}</div>
                        <div style={{ fontSize: 9, fontWeight: 700, color: simTemplate === key ? t.accent : t.textMid, letterSpacing: 0.3 }}>{tmpl.name}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ background: t.codeBg, borderRadius: 12, padding: "14px 16px", border: `1px solid ${t.textFaint}`, marginBottom: 20 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
                    <div style={{ width: 5, height: 5, borderRadius: "50%", background: t.purple }} />
                    <span style={{ fontSize: 9, color: t.purple, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}>PREVIEW</span>
                  </div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: t.textMid, marginBottom: 5 }}>Subject: {SIM_TEMPLATES[simTemplate].subject}</div>
                  <div style={{ fontSize: 11, color: t.textDim, lineHeight: 1.7, fontFamily: "'JetBrains Mono', monospace" }}>{SIM_TEMPLATES[simTemplate].preview}</div>
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <button onClick={handleSendSimulation} disabled={!simEmail.trim() || !simEmail.includes("@") || simSending} className="neon-btn"
                    style={{
                      padding: "11px 28px", borderRadius: 10, fontSize: 12, fontWeight: 700, border: "none",
                      cursor: !simEmail.trim() || !simEmail.includes("@") || simSending ? "default" : "pointer",
                      background: !simEmail.trim() || !simEmail.includes("@") || simSending ? t.textFaint : simMode === "email" ? `linear-gradient(135deg, ${t.purple}, #7c3aed)` : `linear-gradient(135deg, ${t.cyan}, #0284c7)`,
                      color: !simEmail.trim() || !simEmail.includes("@") || simSending ? t.textDim : "white",
                      boxShadow: !simEmail.trim() || !simEmail.includes("@") || simSending ? "none" : `0 4px 16px ${simMode === "email" ? t.purple : t.cyan}40`,
                    }}>
                    {simSending ? "◌  Sending…" : "◉  Send Simulation"}
                  </button>
                </div>
              </GlassCard>
            </div>

            {simSending && (
              <div className="fade-in">
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "32px 24px", marginBottom: 24, textAlign: "center" }}>
                  <div className="sending-ring" style={{ width: 52, height: 52, borderRadius: "50%", margin: "0 auto 14px", background: t.purpleDim, border: `2px solid ${t.purple}30`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <div style={{ width: 22, height: 22, borderRadius: "50%", border: `2px solid ${t.purple}40`, borderTopColor: t.purple, animation: "sweep 0.8s linear infinite" }} />
                  </div>
                  <p style={{ fontSize: 13, color: t.textMid, fontWeight: 600 }}>{simMode === "email" ? "Dispatching email to" : "Preparing simulation for"} <span style={{ color: t.purple, fontFamily: "'JetBrains Mono', monospace" }}>{simEmail}</span></p>
                </GlassCard>
              </div>
            )}

            {displayedSims.length > 0 && (
              <div className="fade-up-d2" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 24 }}>
                <StatCard label="Total Sent" value={displayedSims.length} icon="◉" accentColor={simMode === "email" ? t.purple : t.cyan} total={displayedSims.length} t={t} />
                <StatCard label="Clicked" value={simClickedCount} icon="⚠" accentColor={t.red} total={displayedSims.length} t={t} />
                <StatCard label="Not Clicked" value={simNotClickedCount} icon="✓" accentColor={t.accent} total={displayedSims.length} t={t} />
              </div>
            )}

            {displayedSims.length > 0 && (
              <div className="fade-up-d3">
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "18px 24px", marginBottom: 24 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                    <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>CLICK-THROUGH RATE</span>
                    <span style={{ fontSize: 16, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: simClickedCount / displayedSims.length > 0.4 ? t.red : simClickedCount / displayedSims.length > 0.15 ? t.amber : t.accent }}>{Math.round((simClickedCount / displayedSims.length) * 100)}%</span>
                  </div>
                  <div style={{ height: 8, borderRadius: 4, background: t.textFaint, overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 4, width: `${(simClickedCount / displayedSims.length) * 100}%`, background: simClickedCount / displayedSims.length > 0.4 ? t.red : simClickedCount / displayedSims.length > 0.15 ? t.amber : t.accent, transition: "width 0.8s ease", boxShadow: `0 0 12px ${simClickedCount / displayedSims.length > 0.4 ? t.red : t.accent}30` }} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
                    <span style={{ fontSize: 9, color: t.textDim }}>0% — Excellent</span>
                    <span style={{ fontSize: 9, color: t.textDim }}>100% — Critical</span>
                  </div>
                </GlassCard>
              </div>
            )}

            {displayedSims.length > 0 && (() => {
              const awarenessScore = Math.round((simNotClickedCount / displayedSims.length) * 100);
              const awarenessColor = awarenessScore >= 80 ? t.accent : awarenessScore >= 50 ? t.amber : t.red;
              return (
                <div className="fade-up-d3">
                  <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "18px 24px", marginBottom: 24 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                      <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>USER AWARENESS</span>
                      <span style={{ fontSize: 16, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: awarenessColor }}>{awarenessScore}%</span>
                    </div>
                    <div style={{ height: 8, borderRadius: 4, background: t.textFaint, overflow: "hidden" }}>
                      <div style={{ height: "100%", borderRadius: 4, width: `${awarenessScore}%`, background: awarenessColor, transition: "width 0.8s ease", boxShadow: `0 0 12px ${awarenessColor}30` }} />
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
                      <span style={{ fontSize: 9, color: t.textDim }}>0% — Poor</span>
                      <span style={{ fontSize: 9, color: t.textDim }}>100% — Excellent</span>
                    </div>
                  </GlassCard>
                </div>
              );
            })()}

            <div className="fade-up-d4">
              <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, overflow: "hidden" }}>
                <div style={{ padding: "16px 24px", borderBottom: `1px solid ${t.panelBorder}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>SENT SIMULATIONS</span>
                  <span style={{ fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{displayedSims.length} total</span>
                </div>
                {displayedSims.length === 0 ? (
                  <div style={{ padding: "56px 0", textAlign: "center" }}>
                    <div style={{ fontSize: 36, opacity: 0.08, marginBottom: 10 }}>◉</div>
                    <p style={{ fontSize: 12, color: t.textDim }}>No simulations sent yet. Configure one above to get started.</p>
                  </div>
                ) : (
                  <div style={{ padding: 12, display: "flex", flexDirection: "column", gap: 10 }}>
                    {displayedSims.map((sim, idx) => {
                      const isClicked = sim.status === "Clicked";
                      const cardColor = isClicked ? t.red : t.accent;
                      return (
                        <div key={sim.id} className="sim-card" style={{
                          background: `${t.textFaint}30`, border: `1px solid ${t.panelBorder}`,
                          borderRadius: 14, padding: "16px 18px", animationDelay: `${idx * 60}ms`,
                          borderLeftWidth: 3, borderLeftColor: `${cardColor}40`,
                        }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                              <span style={{ fontSize: 16 }}>{sim.icon}</span>
                              <div>
                                <div style={{ fontSize: 12, fontWeight: 700, color: t.text }}>{sim.email}</div>
                                <div style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>{sim.templateName} · {new Date(sim.sentAt).toLocaleString()}</div>
                              </div>
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              {sim.mode === "email" ? (
                                <button onClick={() => window.open(`/sandbox?id=${sim.id}`, "_blank")} style={{ display: "flex", alignItems: "center", gap: 5, padding: "4px 12px", borderRadius: 8, border: `1px solid ${t.purple}25`, background: t.purpleDim, cursor: "pointer" }}>
                                  <span style={{ fontSize: 9, fontWeight: 700, color: t.purple, fontFamily: "'JetBrains Mono', monospace" }}>👁 LINK</span>
                                </button>
                              ) : (
                                <button onClick={() => setSandboxSim(sim)} style={{ display: "flex", alignItems: "center", gap: 5, padding: "4px 12px", borderRadius: 8, border: `1px solid ${t.cyan}25`, background: t.cyanDim, cursor: "pointer" }}>
                                  <span style={{ fontSize: 9, fontWeight: 700, color: t.cyan, fontFamily: "'JetBrains Mono', monospace" }}>👁 VIEW</span>
                                </button>
                              )}
                              <button onClick={() => handleToggleSimStatus(sim.id)} style={{ display: "flex", alignItems: "center", gap: 5, padding: "4px 12px", borderRadius: 8, border: `1px solid ${cardColor}25`, background: `${cardColor}10`, cursor: "pointer" }}>
                                <div style={{ width: 6, height: 6, borderRadius: "50%", background: cardColor, boxShadow: `0 0 6px ${cardColor}50` }} />
                                <span style={{ fontSize: 9, fontWeight: 700, color: cardColor, fontFamily: "'JetBrains Mono', monospace" }}>{isClicked ? "CLICKED" : "NOT CLICKED"}</span>
                              </button>
                            </div>
                          </div>
                          <div style={{ background: t.codeBg, borderRadius: 10, padding: "11px 13px", border: `1px solid ${t.textFaint}` }}>
                            <div style={{ fontSize: 11, fontWeight: 700, color: t.textMid, marginBottom: 3 }}>Subject: {sim.subject}</div>
                            <div style={{ fontSize: 10, color: t.textDim, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace" }}>{sim.preview}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </GlassCard>
            </div>
          </div>
        )}

        {/* ═══ TRAINING PAGE ═══ */}
        {page === "training" && (
          <div key="training" className="relative z-10 page-transition" style={{ maxWidth: 760, margin: "0 auto", padding: "44px 24px 80px" }}>
            <div className="fade-up" style={{ marginBottom: 36 }}>
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 8,
                fontSize: 9, letterSpacing: 5, textTransform: "uppercase", color: t.cyan,
                marginBottom: 12, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
                textShadow: `0 0 15px ${t.cyanGlow}`,
                padding: "5px 14px", borderRadius: 20,
                background: `linear-gradient(135deg, ${t.cyanDim}, rgba(0,212,255,0.04))`,
                border: `1px solid ${t.cyan}15`,
              }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: t.cyan, boxShadow: `0 0 6px ${t.cyan}` }} />
                AWARENESS TRAINING
              </div>
              <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: -1, fontFamily: "'Sora', sans-serif" }}>Phishing Quiz</h1>
              <p style={{ fontSize: 13, color: t.textMid, marginTop: 6, fontWeight: 400 }}>Can you tell real emails from phishing attempts?</p>
            </div>

            {/* Progress dots indicator */}
            <div className="fade-up-d1" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6, marginBottom: 20 }}>
              {TRAINING_QUESTIONS.length > 0 && Array.from({ length: TRAINING_QUESTIONS.length }).map((_, i) => (
                <div key={i} style={{
                  width: i === tqIndex && !tFinished ? 28 : 8, height: 8, borderRadius: 4,
                  background: i < tqIndex || tFinished ? t.accent : i === tqIndex && !tFinished ? `linear-gradient(90deg, ${t.cyan}, ${t.accent})` : "rgba(255,255,255,0.08)",
                  transition: "all 0.4s cubic-bezier(0.22,1,0.36,1)",
                  boxShadow: i === tqIndex && !tFinished ? `0 0 12px ${t.cyanGlow}` : "none",
                }} />
              ))}
            </div>

            <div className="fade-up-d1" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
              {[
                { label: "SCORE", value: `${tScore}/${TRAINING_QUESTIONS.length}`, color: t.accent },
                { label: "STREAK", value: `${tStreak}${tStreak >= 3 ? " 🔥" : ""}`, color: tStreak >= 3 ? "#f97316" : t.text },
                { label: "QUESTION", value: `${tFinished ? TRAINING_QUESTIONS.length : tqIndex + 1}/${TRAINING_QUESTIONS.length}`, color: t.text },
                { label: "TIMER", value: tFinished ? "—" : tAnswered ? "—" : `${tTimer}s`, color: !tFinished && !tAnswered && tTimer <= 3 ? t.red : t.text },
              ].map((s, i) => (
                <GlassCard key={i} style={{ background: "rgba(10,12,22,0.8)", border: `1px solid ${t.panelBorder}`, padding: "14px 14px", textAlign: "center" }}>
                  <div style={{ fontSize: 8, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>{s.label}</div>
                  <div style={{ fontSize: 24, fontWeight: 800, color: s.color, fontFamily: "'JetBrains Mono', monospace" }}>{s.value}</div>
                </GlassCard>
              ))}
            </div>

            {!tFinished && !tAnswered && (
              <div style={{ height: 3, borderRadius: 2, background: t.textFaint, marginBottom: 24, overflow: "hidden" }}>
                <div style={{ height: "100%", borderRadius: 2, width: `${(tTimer / 15) * 100}%`, background: tTimer <= 3 ? t.red : tTimer <= 5 ? t.amber : t.accent, transition: "width 1s linear, background 0.3s" }} />
              </div>
            )}

            {!tFinished && TRAINING_QUESTIONS.length === 0 ? (
              <GlassCard className="fade-up-d2" style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: 28, textAlign: "center" }}>
                <p style={{ color: t.textMid }}>Loading questions...</p>
              </GlassCard>
            ) : !tFinished ? (
              <GlassCard className="fade-up-d2" style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: 28 }}>
                <div style={{ padding: "18px 20px", borderRadius: 14, background: t.codeBg, border: `1px solid ${t.textFaint}`, marginBottom: 22 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                    <span style={{ fontSize: 14 }}>📧</span>
                    <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>MESSAGE CONTENT</span>
                  </div>
                  <p style={{ fontSize: 12, color: t.textMid, lineHeight: 1.8, margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>{TRAINING_QUESTIONS[tqIndex].text}</p>
                </div>

                {!tAnswered ? (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                    <button onClick={() => handleTrainingAnswer("Safe")} className="neon-btn" style={{
                      padding: "16px 22px", borderRadius: 14, fontSize: 15, fontWeight: 800, cursor: "pointer",
                      background: `linear-gradient(135deg, ${t.accentDim}, rgba(0,255,136,0.15))`,
                      border: `1px solid ${t.accent}30`, color: t.accent,
                      boxShadow: `0 4px 16px rgba(0,255,136,0.1)`,
                    }}>✓  Safe</button>
                    <button onClick={() => handleTrainingAnswer("Phishing")} className="neon-btn" style={{
                      padding: "16px 22px", borderRadius: 14, fontSize: 15, fontWeight: 800, cursor: "pointer",
                      background: `linear-gradient(135deg, ${t.redDim}, rgba(255,51,102,0.12))`,
                      border: `1px solid ${t.red}25`, color: t.red,
                      boxShadow: `0 4px 16px rgba(255,51,102,0.1)`,
                    }}>⚠  Phishing</button>
                  </div>
                ) : (
                  <div>
                    <div style={{ padding: "16px 20px", borderRadius: 14, marginBottom: 16, textAlign: "center", background: tAnswered === "correct" ? t.accentDim : t.redDim, border: `1px solid ${tAnswered === "correct" ? `${t.accent}30` : `${t.red}25`}` }}>
                      <div style={{ fontSize: 26, marginBottom: 5 }}>{tAnswered === "correct" ? "✅" : tAnswered === "timeout" ? "⏱" : "❌"}</div>
                      <div style={{ fontSize: 15, fontWeight: 800, color: tAnswered === "correct" ? t.accent : t.red }}>
                        {tAnswered === "correct" ? "Correct!" : tAnswered === "timeout" ? "Time's Up!" : "Wrong!"}
                      </div>
                      {tStreak >= 3 && tAnswered === "correct" && <div style={{ fontSize: 11, color: "#f97316", marginTop: 4, fontFamily: "'JetBrains Mono', monospace" }}>🔥 {tStreak} streak!</div>}
                    </div>

                    <div style={{ padding: "12px 16px", borderRadius: 12, marginBottom: 12, background: t.codeBg, border: `1px solid ${t.textFaint}`, display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 2 }}>ANSWER:</span>
                      <span style={{ fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 6, fontFamily: "'JetBrains Mono', monospace", background: TRAINING_QUESTIONS[tqIndex].answer === "Safe" ? t.accentDim : t.redDim, color: TRAINING_QUESTIONS[tqIndex].answer === "Safe" ? t.accent : t.red, border: `1px solid ${TRAINING_QUESTIONS[tqIndex].answer === "Safe" ? `${t.accent}30` : `${t.red}25`}` }}>{TRAINING_QUESTIONS[tqIndex].answer.toUpperCase()}</span>
                    </div>

                    <div style={{ padding: "14px 18px", borderRadius: 12, background: t.cyanDim, border: `1px solid ${t.cyan}20`, marginBottom: 18 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
                        <div style={{ width: 5, height: 5, borderRadius: "50%", background: t.cyan }} />
                        <span style={{ fontSize: 9, color: t.cyan, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>EXPLANATION</span>
                      </div>
                      <p style={{ fontSize: 11.5, color: t.textMid, lineHeight: 1.7, margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>{TRAINING_QUESTIONS[tqIndex].explanation}</p>
                    </div>

                    <div style={{ display: "flex", justifyContent: "center" }}>
                      <button onClick={handleTrainingNext} className="neon-btn" style={{ padding: "11px 32px", borderRadius: 12, fontSize: 12, fontWeight: 700, border: "none", cursor: "pointer", background: `linear-gradient(135deg, ${t.cyan}, #0284c7)`, color: "white", boxShadow: `0 4px 16px ${t.cyanGlow}` }}>
                        {tqIndex + 1 >= TRAINING_QUESTIONS.length ? "See Results" : "Next Question →"}
                      </button>
                    </div>
                  </div>
                )}
              </GlassCard>
            ) : (
              <GlassCard className="fade-up" style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "44px 32px", textAlign: "center" }}>
                <div style={{ fontSize: 44, marginBottom: 14 }}>{tScore / TRAINING_QUESTIONS.length >= 0.8 ? "🏆" : tScore / TRAINING_QUESTIONS.length >= 0.5 ? "👍" : "📚"}</div>
                <h2 style={{ fontSize: 24, fontWeight: 800, marginBottom: 8 }}>Quiz Complete!</h2>
                <p style={{ fontSize: 15, fontWeight: 700, marginBottom: 22, color: tScore / TRAINING_QUESTIONS.length >= 0.8 ? t.accent : tScore / TRAINING_QUESTIONS.length >= 0.5 ? t.amber : t.red }}>
                  {tScore / TRAINING_QUESTIONS.length >= 0.8 ? "Excellent! You're phishing-proof!" : tScore / TRAINING_QUESTIONS.length >= 0.5 ? "Good effort! Keep learning." : "Needs improvement — stay vigilant!"}
                </p>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 28 }}>
                  {[
                    { value: `${tScore}/${TRAINING_QUESTIONS.length}`, label: "CORRECT", color: t.accent },
                    { value: `${Math.round((tScore / TRAINING_QUESTIONS.length) * 100)}%`, label: "ACCURACY", color: t.purple },
                    { value: `${tBestStreak} 🔥`, label: "BEST STREAK", color: "#f97316" },
                  ].map((s, i) => (
                    <GlassCard key={i} style={{ background: t.codeBg, border: `1px solid ${t.textFaint}`, padding: "16px 12px" }}>
                      <div style={{ fontSize: 26, fontWeight: 800, color: s.color, fontFamily: "'JetBrains Mono', monospace" }}>{s.value}</div>
                      <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>{s.label}</div>
                    </GlassCard>
                  ))}
                </div>

                <button onClick={handleTrainingRestart} className="neon-btn" style={{ padding: "12px 36px", borderRadius: 14, fontSize: 13, fontWeight: 700, border: "none", cursor: "pointer", background: `linear-gradient(135deg, ${t.cyan}, #0284c7)`, color: "white", boxShadow: `0 4px 16px ${t.cyanGlow}` }}>Try Again</button>
              </GlassCard>
            )}
          </div>
        )}

        {/* ═══ SCREENSHOT SCANNER ═══ */}
        {page === "screenshot" && (
          <div key="screenshot" className="relative z-10 page-transition" style={{ maxWidth: 760, margin: "0 auto", padding: "48px 24px 80px" }}>
            <div className="fade-up" style={{ textAlign: "center", marginBottom: 52 }}>
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 8,
                fontSize: 9, letterSpacing: 5, textTransform: "uppercase", color: t.cyan,
                marginBottom: 18, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
                textShadow: `0 0 20px ${t.cyanGlow}`,
                padding: "6px 16px", borderRadius: 20,
                background: `linear-gradient(135deg, ${t.cyanDim}, rgba(0,212,255,0.04))`,
                border: `1px solid ${t.cyan}15`,
              }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: t.cyan, boxShadow: `0 0 6px ${t.cyan}` }} />
                SCREENSHOT SCANNER
              </div>
              <h1 style={{ fontSize: 42, fontWeight: 800, letterSpacing: -2, lineHeight: 1.1, fontFamily: "'Sora', sans-serif" }}>
                <span style={{ backgroundImage: `linear-gradient(135deg, ${t.cyan}, ${t.purple})`, WebkitBackgroundClip: "text", backgroundClip: "text", WebkitTextFillColor: "transparent", color: "transparent" }}>
                  Scan Screenshots
                </span>
                <br />
                <span style={{ color: t.textMid, fontWeight: 300, fontSize: 28, letterSpacing: -0.5 }}>Detect Phishing from Images</span>
              </h1>
              <p style={{ marginTop: 14, fontSize: 10, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 2.5 }}>
                GEMINI VISION OCR  ·  AI + RULE ENGINE  ·  INSTANT ANALYSIS
              </p>
            </div>

            <div className="fade-up-d1">
              <GlassCard style={{ background: t.panel, border: `1px solid ${ssDragOver ? t.cyan : t.panelBorder}`, padding: 26, transition: "border-color 0.2s" }}>
                <input ref={ssFileRef} type="file" accept="image/*" style={{ display: "none" }}
                  onChange={(e) => { if (e.target.files[0]) handleScreenshotFile(e.target.files[0]); }} />

                {!ssFile ? (
                  <div
                    onDragOver={(e) => { e.preventDefault(); setSsDragOver(true); }}
                    onDragLeave={() => setSsDragOver(false)}
                    onDrop={(e) => { e.preventDefault(); setSsDragOver(false); if (e.dataTransfer.files[0]) handleScreenshotFile(e.dataTransfer.files[0]); }}
                    onClick={() => ssFileRef.current?.click()}
                    style={{
                      border: `2px dashed ${ssDragOver ? t.cyan : t.panelBorder}`, borderRadius: 16, padding: "56px 24px",
                      textAlign: "center", cursor: "pointer", transition: "all 0.2s",
                      background: ssDragOver ? t.cyanDim : "transparent",
                    }}
                  >
                    <div style={{ fontSize: 40, marginBottom: 16, opacity: 0.6 }}>📸</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: t.text, marginBottom: 8 }}>
                      Drop a screenshot here or click to upload
                    </div>
                    <div style={{ fontSize: 11, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                      Supports PNG, JPG, WEBP — screenshots of emails, messages, etc.
                    </div>
                    <button className="neon-btn" style={{
                      marginTop: 20, padding: "10px 24px", borderRadius: 10, fontSize: 12, fontWeight: 700,
                      background: `linear-gradient(135deg, ${t.cyan}, ${t.purple})`, border: "none", color: "white", cursor: "pointer",
                      boxShadow: `0 4px 20px ${t.cyanGlow}`,
                    }}>
                      Upload Screenshot
                    </button>
                  </div>
                ) : (
                  <div>
                    <div style={{ position: "relative", marginBottom: 16 }}>
                      <img src={ssFile} alt="Screenshot preview" style={{
                        width: "100%", maxHeight: 320, objectFit: "contain", borderRadius: 12,
                        border: `1px solid ${t.textFaint}`, background: t.codeBg,
                      }} />
                      <button onClick={() => { setSsFile(null); setSsImage(null); setSsResult(null); setSsExtractedText(""); setSsAiReason(""); setSsAiPoints([]); }}
                        style={{
                          position: "absolute", top: 8, right: 8, width: 28, height: 28, borderRadius: 8,
                          background: "rgba(0,0,0,0.7)", border: `1px solid ${t.textFaint}`, color: t.textMid,
                          fontSize: 14, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
                        }}>×</button>
                    </div>
                    <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                      <button onClick={() => { ssFileRef.current?.click(); }} className="neon-btn"
                        style={{ padding: "9px 16px", borderRadius: 10, fontSize: 12, fontWeight: 600, cursor: "pointer", background: t.textFaint, border: `1px solid ${t.panelBorder}`, color: t.textMid }}>
                        Change Image
                      </button>
                      <button onClick={handleScreenshotScan} disabled={ssScanning} className="neon-btn"
                        style={{
                          padding: "9px 24px", borderRadius: 10, fontSize: 12, fontWeight: 700, border: "none",
                          cursor: ssScanning ? "default" : "pointer",
                          background: ssScanning ? t.textFaint : `linear-gradient(135deg, ${t.cyan}, ${t.purple})`,
                          color: ssScanning ? t.textDim : "white",
                          boxShadow: ssScanning ? "none" : `0 4px 20px ${t.cyanGlow}`,
                        }}>
                        {ssScanning ? "Analyzing…" : "⌕  Scan Screenshot"}
                      </button>
                    </div>
                  </div>
                )}
              </GlassCard>
            </div>

            {ssScanning && (
              <div className="fade-in" style={{ marginTop: 32 }}>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "36px 28px", textAlign: "center" }}>
                  <RadarScanAnimation t={t} />
                  <p style={{ fontSize: 13, color: t.textMid, marginTop: 18, fontWeight: 600 }}>Extracting & analyzing screenshot…</p>
                  <div style={{ marginTop: 20, maxWidth: 320, marginLeft: "auto", marginRight: "auto" }}>
                    {ssScanSteps.map((step, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 7, opacity: i <= ssScanStep ? 1 : 0.2, transition: "opacity 0.3s" }}>
                        <div style={{
                          width: 18, height: 18, borderRadius: 5, fontSize: 9, display: "flex", alignItems: "center", justifyContent: "center",
                          background: i <= ssScanStep ? t.cyanDim : t.textFaint,
                          color: i <= ssScanStep ? t.cyan : t.textDim, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
                          border: `1px solid ${i <= ssScanStep ? `${t.cyan}30` : t.textFaint}`,
                        }}>{i < ssScanStep ? "✓" : i + 1}</div>
                        <span style={{ fontSize: 11, color: i <= ssScanStep ? t.textMid : t.textDim }}>{step}</span>
                        <div style={{ flex: 1 }}>{i <= ssScanStep && <div className="scan-step-bar"><div className="scan-step-fill" /></div>}</div>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              </div>
            )}

            {ssExtractedText && !ssScanning && (
              <div className="fade-up-d1" style={{ marginTop: 32 }}>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "22px 24px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                    <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.cyan, boxShadow: `0 0 8px ${t.cyan}` }} />
                    <span style={{ fontSize: 9, color: t.cyan, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>EXTRACTED TEXT</span>
                  </div>
                  <div style={{
                    padding: "16px 18px", borderRadius: 12, background: t.codeBg, border: `1px solid ${t.textFaint}`,
                    fontSize: 12, lineHeight: 1.8, color: t.textDim, fontFamily: "'JetBrains Mono', monospace",
                    whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 200, overflowY: "auto",
                  }}>{highlightText(ssExtractedText)}</div>
                </GlassCard>
              </div>
            )}

            {ssResult && !ssScanning && (
              <div className="fade-up-d2" style={{ marginTop: 32 }}>
                <GlassCard style={{ background: t.panel, border: `1px solid ${t.panelBorder}`, padding: "36px 28px", borderColor: `${statusColor(ssResult.status)}15`, boxShadow: `0 0 60px ${statusColor(ssResult.status)}06` }} glow={`${statusColor(ssResult.status)}08`}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 32 }}>
                    <ScoreRing score={ssResult.score} status={ssResult.status} t={t} />
                    <div style={{ marginTop: 18, padding: "5px 18px", borderRadius: 8, fontSize: 12, fontWeight: 700, background: `${statusColor(ssResult.status)}10`, color: statusColor(ssResult.status), border: `1px solid ${statusColor(ssResult.status)}20`, letterSpacing: 0.5, fontFamily: "'JetBrains Mono', monospace" }}>
                      {ssResult.status === "Phishing" ? "⚠  PHISHING DETECTED" : ssResult.status === "Suspicious" ? "△  SUSPICIOUS CONTENT" : "✓  APPEARS SAFE"}
                    </div>
                    {(() => {
                      const riskLevel = ssResult.score >= 80 ? "CRITICAL" : ssResult.score >= 60 ? "HIGH" : ssResult.score >= 30 ? "MEDIUM" : "LOW";
                      const riskColor = ssResult.score >= 80 ? t.red : ssResult.score >= 60 ? "#f97316" : ssResult.score >= 30 ? t.amber : t.accent;
                      const riskIcon = ssResult.status === "Phishing" ? "🚨" : ssResult.status === "Suspicious" ? "⚠️" : "✅";
                      const riskWord = ssResult.status === "Phishing" ? "Dangerous" : ssResult.status === "Suspicious" ? "Suspicious" : "Safe";
                      return (
                        <div style={{ marginTop: 14, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                          <div style={{ fontSize: 30 }}>{riskIcon}</div>
                          <div style={{ fontSize: 18, fontWeight: 800, color: riskColor }}>{riskWord}</div>
                          <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 3, color: riskColor, fontFamily: "'JetBrains Mono', monospace", padding: "3px 12px", borderRadius: 6, background: `${riskColor}10`, border: `1px solid ${riskColor}25` }}>{riskLevel}</span>
                        </div>
                      );
                    })()}
                  </div>

                  {ssEngineDisagree && (
                    <div style={{ marginBottom: 20, padding: "12px 16px", borderRadius: 10, background: t.cyanDim, border: `1px solid ${t.cyan}20`, display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontSize: 16 }}>🔀</span>
                      <span style={{ fontSize: 11, color: t.cyan, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5 }}>
                        AI and heuristic engines disagree. Showing AI-preferred result for higher accuracy.
                      </span>
                    </div>
                  )}

                  <div style={{ marginBottom: 28 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 2 }}>THREAT LEVEL</span>
                      <span style={{ fontSize: 9, color: statusColor(ssResult.status), fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>{ssResult.score}/100</span>
                    </div>
                    <div style={{ height: 5, borderRadius: 3, background: t.textFaint, overflow: "hidden" }}>
                      <div style={{ height: "100%", borderRadius: 3, width: `${ssResult.score}%`, backgroundImage: `linear-gradient(90deg, ${t.accent}, ${ssResult.score > 30 ? t.amber : t.accent}, ${ssResult.score > 65 ? t.red : t.amber})`, transition: "width 1.2s cubic-bezier(0.22,1,0.36,1)", boxShadow: `0 0 12px ${statusColor(ssResult.status)}40` }} />
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
                      {["Safe", "Low", "Medium", "High", "Critical"].map((l) => <span key={l} style={{ fontSize: 8, color: t.textDim }}>{l}</span>)}
                    </div>
                  </div>

                  {ssResult.status !== "Safe" && ssExtractedText && (() => {
                    const attack = detectAttackType(ssExtractedText);
                    return (
                      <div style={{ marginBottom: 24, padding: "14px 18px", borderRadius: 12, background: `${attack.color}08`, border: `1px solid ${attack.color}18`, display: "flex", alignItems: "center", gap: 12 }}>
                        <span style={{ fontSize: 22 }}>{attack.icon}</span>
                        <div>
                          <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace", marginBottom: 3 }}>ATTACK TYPE</div>
                          <div style={{ fontSize: 14, fontWeight: 700, color: attack.color }}>{attack.type}</div>
                        </div>
                      </div>
                    );
                  })()}

                  {ssResult.signals.length > 0 ? (
                    <div>
                      <span style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>TOP SIGNALS — {ssResult.signals.length} FOUND</span>
                      <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 12 }}>
                        {ssResult.signals.slice(0, 5).map((s, i) => <SignalCard key={i} signal={s} index={i} t={t} />)}
                      </div>
                    </div>
                  ) : (
                    <p style={{ textAlign: "center", fontSize: 13, color: t.textDim, padding: "18px 0" }}>No phishing indicators detected in extracted text.</p>
                  )}

                  {ssAiReason && (
                    <div style={{ marginTop: 22, padding: "18px 20px", borderRadius: 12, background: t.purpleDim, border: `1px solid ${t.purple}25` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.purple, boxShadow: `0 0 8px ${t.purple}` }} />
                        <span style={{ fontSize: 9, color: t.purple, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>AI ANALYSIS</span>
                      </div>
                      <p style={{ fontSize: 12, color: t.textMid, lineHeight: 1.7, margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>{ssAiReason}</p>
                      {ssAiPoints.length > 0 && (
                        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
                          {ssAiPoints.map((point, i) => (
                            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                              <span style={{ color: t.purple, fontSize: 12, lineHeight: "18px", flexShrink: 0 }}>▸</span>
                              <span style={{ fontSize: 11.5, color: t.textMid, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace" }}>{point}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  <div style={{ marginTop: 22, padding: "18px 20px", borderRadius: 12, background: t.accentDim, border: `1px solid ${t.accent}20` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: t.accent, boxShadow: `0 0 8px ${t.accent}` }} />
                      <span style={{ fontSize: 9, color: t.accent, fontWeight: 700, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace" }}>RECOMMENDED ACTIONS</span>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {(ssResult.status === "Phishing" ? ["Do not interact with the content shown in this screenshot", "Do not click any links or scan QR codes from this message", "Report this to your IT security team", "If you already responded, change your passwords immediately"] : ssResult.status === "Suspicious" ? ["Verify the sender through official channels", "Do not click links shown in the screenshot", "Contact the organization directly to confirm legitimacy"] : ["Content appears safe, but always stay vigilant", "Verify sender identity for any unexpected messages"]).map((tip, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                          <span style={{ color: t.accent, fontSize: 12, lineHeight: "18px", flexShrink: 0 }}>▸</span>
                          <span style={{ fontSize: 11.5, color: t.textMid, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace" }}>{tip}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div style={{ marginTop: 14, textAlign: "center" }}>
                    <span style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1 }}>Screenshot OCR via Gemini Vision · AI + rule-based detection</span>
                  </div>
                </GlassCard>
              </div>
            )}
          </div>
        )}

        {/* ═══ FOOTER ═══ */}
        <footer className="relative z-10" style={{
          textAlign: "center", padding: "32px 24px 24px",
          borderTop: `1px solid ${t.panelBorder}`,
        }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginBottom: 8 }}>
            <div style={{ width: 4, height: 4, borderRadius: "50%", background: t.accent, boxShadow: `0 0 6px ${t.accent}` }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: t.textMid, fontFamily: "'Sora', sans-serif", letterSpacing: 0.5 }}>PhishGuard</span>
            <span style={{ fontSize: 8, color: t.textDim, fontFamily: "'JetBrains Mono', monospace" }}>PRO</span>
          </div>
          <p style={{ fontSize: 9, color: t.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1.5 }}>
            HYBRID AI + RULE-BASED DETECTION · BUILT FOR SECURITY TEAMS
          </p>
        </footer>

        {/* ═══ SANDBOX OVERLAY ═══ */}
        {sandboxSim && (
          <div className="fade-in" style={{ position: "fixed", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: 24, zIndex: 9999, background: "rgba(5,5,8,0.92)", backdropFilter: "blur(32px)" }}>
            <div className="modal-enter" style={{
              background: `${t.red}08`, border: `1px solid ${t.red}30`,
              borderRadius: 24, padding: "44px 36px", maxWidth: 640, width: "100%", textAlign: "left",
              boxShadow: `0 20px 60px ${t.redGlow}, inset 0 0 0 2px ${t.red}10`, position: "relative",
            }}>
              <button onClick={() => setSandboxSim(null)} style={{ position: "absolute", top: 18, right: 22, background: "none", border: "none", fontSize: 26, color: t.textDim, cursor: "pointer" }}>×</button>

              <div style={{ textAlign: "center", marginBottom: 32 }}>
                <div style={{ fontSize: 56, marginBottom: 14, filter: `drop-shadow(0 0 20px ${t.redGlow})` }}>🚨</div>
                <h2 style={{ fontSize: 28, fontWeight: 900, color: t.red, letterSpacing: -1, marginBottom: 8 }}>Oops! You've Been Phished.</h2>
                <p style={{ fontSize: 14, color: t.textMid, lineHeight: 1.6 }}>This was a simulated phishing attack designed to test your security awareness.<br /><span style={{ color: t.red, fontWeight: 700 }}>If this were real, your data would be compromised.</span></p>
              </div>

              <div style={{ background: t.codeBg, border: `1px solid ${t.textFaint}`, borderRadius: 16, padding: "22px", marginBottom: 28 }}>
                <div style={{ fontSize: 9, color: t.textDim, letterSpacing: 2, fontFamily: "'JetBrains Mono', monospace", marginBottom: 14 }}>ANALYZING THE ATTACK</div>
                <div style={{ display: "flex", alignItems: "flex-start", gap: 14, marginBottom: 22 }}>
                  <div style={{ fontSize: 32 }}>{sandboxSim.icon || "🛡️"}</div>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 800, color: t.text, marginBottom: 5 }}>{sandboxSim.templateName || "Simulation"}</div>
                    <div style={{ fontSize: 12, color: t.textMid, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace" }}>{sandboxSim.preview || "This is a simulated threat payload."}</div>
                  </div>
                </div>
                <div style={{ padding: "16px", background: t.amberDim, border: `1px solid ${t.amber}25`, borderRadius: 12 }}>
                  <div style={{ color: t.amber, fontWeight: 700, fontSize: 13, marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
                    <span>🛡️</span> {sandboxSim.template === "tata_aia" ? "TATA AIA Security Tip" : "Red Flags You Missed"}
                  </div>
                  {sandboxSim.template === "tata_aia" ? (
                    <div style={{ color: t.textMid, fontSize: 12, lineHeight: 1.6 }}>TATA AIA Life Insurance will <strong>never</strong> ask you to pay your premium through an unverified SMS link or WhatsApp message. Always use the official <strong>tataaia.com</strong> portal for policy renewals and KYC updates. Never share OTPs over the phone.</div>
                  ) : (
                    <ul style={{ color: t.textMid, fontSize: 12, lineHeight: 1.6, paddingLeft: 20, margin: 0 }}>
                      <li style={{ marginBottom: 5 }}>Creating a false sense of extreme urgency.</li>
                      <li style={{ marginBottom: 5 }}>Requesting sensitive actions (login, payment) via direct link.</li>
                      <li>Using an unexpected or spoofed sender address.</li>
                    </ul>
                  )}
                </div>
              </div>

              <button onClick={() => setSandboxSim(null)} className="neon-btn" style={{ width: "100%", padding: "14px", borderRadius: 12, fontSize: 14, fontWeight: 800, background: t.red, color: "white", border: "none", cursor: "pointer", boxShadow: `0 4px 20px ${t.redGlow}` }}>
                I Understand, Return to Dashboard
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}