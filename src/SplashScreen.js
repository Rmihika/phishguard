import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import "./SplashScreen.css";

/* ═══════════════════════════════════════════════════════════
   SYSTEM BOOT MESSAGES
   ═══════════════════════════════════════════════════════════ */

const BOOT_MESSAGES = [
  "Initializing Threat Engine...",
  "Loading Neural Defense Systems...",
  "Calibrating AI Detection Models...",
  "Scanning Threat Intelligence Feeds...",
  "Analyzing Threat Vectors...",
  "Deploying Real-Time Shields...",
  "System Online — All Defenses Active",
];

/* ═══════════════════════════════════════════════════════════
   TYPING TEXT
   ═══════════════════════════════════════════════════════════ */

function TypingText({ messages, durationMs }) {
  const [msgIndex, setMsgIndex] = useState(0);
  const [displayed, setDisplayed] = useState("");
  const [glitch, setGlitch] = useState(false);
  const charRef = useRef(0);
  const timerRef = useRef(null);

  const msPerMessage = durationMs / messages.length;
  const typeSpeed = 28;

  const advanceMessage = useCallback(() => {
    setMsgIndex((prev) => {
      const next = prev + 1;
      if (next >= messages.length) return prev;
      charRef.current = 0;
      setDisplayed("");
      setGlitch(true);
      setTimeout(() => setGlitch(false), 150);
      return next;
    });
  }, [messages.length]);

  useEffect(() => {
    const msg = messages[msgIndex];
    if (!msg) return;

    timerRef.current = setInterval(() => {
      charRef.current += 1;
      if (charRef.current <= msg.length) {
        setDisplayed(msg.slice(0, charRef.current));
      } else {
        clearInterval(timerRef.current);
      }
    }, typeSpeed);

    const nextTimer = setTimeout(advanceMessage, msPerMessage);

    return () => {
      clearInterval(timerRef.current);
      clearTimeout(nextTimer);
    };
  }, [msgIndex, messages, msPerMessage, advanceMessage]);

  return (
    <div className={`splash-status-line ${glitch ? "splash-glitch" : ""}`}>
      {displayed}
      <span className="splash-cursor" />
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   LOADER ANIMATION (Radar Scanner)
   ═══════════════════════════════════════════════════════════ */

function LoaderAnimation() {
  return (
    <motion.div
      className="splash-scanner"
      initial={{ scale: 0.6, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
    >
      {/* Rings */}
      <div className="scanner-ring-outer" />
      <div className="scanner-ring-mid" />
      <div className="scanner-ring-inner" />

      {/* Crosshairs */}
      <div className="scanner-crosshair-h" />
      <div className="scanner-crosshair-v" />

      {/* Rotating sweep */}
      <div className="scanner-sweep" />

      {/* Data dots */}
      <div className="scanner-dot scanner-dot-1" />
      <div className="scanner-dot scanner-dot-2" />
      <div className="scanner-dot scanner-dot-3" />

      {/* Center energy orb */}
      <div className="scanner-core">
        <div className="scanner-core-orb" />
      </div>

      {/* Shield icon */}
      <div className="scanner-shield">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" opacity="0.7" />
        </svg>
      </div>
    </motion.div>
  );
}

/* ═══════════════════════════════════════════════════════════
   FLOATING PARTICLES
   ═══════════════════════════════════════════════════════════ */

function Particles() {
  const items = Array.from({ length: 20 }, (_, i) => ({
    id: i,
    left: `${5 + Math.random() * 90}%`,
    top: `${30 + Math.random() * 60}%`,
    delay: `${Math.random() * 4}s`,
    duration: `${3 + Math.random() * 3}s`,
    size: 1.5 + Math.random() * 2,
    color: ["#00ff88", "#00d4ff", "#a78bfa"][i % 3],
  }));

  return (
    <div className="splash-particles">
      {items.map((p) => (
        <div
          key={p.id}
          className="splash-particle"
          style={{
            left: p.left,
            top: p.top,
            width: p.size,
            height: p.size,
            background: p.color,
            animationDelay: p.delay,
            animationDuration: p.duration,
          }}
        />
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   PROGRESS BAR
   ═══════════════════════════════════════════════════════════ */

function ProgressBar({ progress }) {
  return (
    <motion.div
      className="splash-progress-container"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className="splash-progress-track">
        <div
          className="splash-progress-fill"
          style={{ width: `${progress}%` }}
        />
        <div
          className="splash-progress-glow"
          style={{ left: `calc(${progress}% - 10px)` }}
        />
      </div>
      <div className="splash-progress-pct">{Math.round(progress)}%</div>
    </motion.div>
  );
}

/* ═══════════════════════════════════════════════════════════
   SPLASH SCREEN (main export)
   ═══════════════════════════════════════════════════════════ */

const SPLASH_DURATION = 3200;

export default function SplashScreen({ onComplete }) {
  const [progress, setProgress] = useState(0);
  const [visible, setVisible] = useState(true);
  const startRef = useRef(Date.now());

  useEffect(() => {
    const raf = { id: null };

    function tick() {
      const elapsed = Date.now() - startRef.current;
      const pct = Math.min((elapsed / SPLASH_DURATION) * 100, 100);

      // Ease-out curve for more natural progress feel
      const eased = 100 * (1 - Math.pow(1 - pct / 100, 2.5));
      setProgress(eased);

      if (elapsed < SPLASH_DURATION) {
        raf.id = requestAnimationFrame(tick);
      } else {
        setProgress(100);
        setTimeout(() => setVisible(false), 300);
      }
    }

    raf.id = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.id);
  }, []);

  useEffect(() => {
    if (!visible && onComplete) {
      const t = setTimeout(onComplete, 500);
      return () => clearTimeout(t);
    }
  }, [visible, onComplete]);

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          className="splash-root"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 0.96 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        >
          {/* Background effects */}
          <div className="splash-grid" />
          <Particles />

          {/* Corner brackets */}
          <div className="splash-corner splash-corner-tl" />
          <div className="splash-corner splash-corner-tr" />
          <div className="splash-corner splash-corner-bl" />
          <div className="splash-corner splash-corner-br" />

          {/* Radar scanner */}
          <LoaderAnimation />

          {/* System text */}
          <motion.div
            className="splash-text-area"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="splash-title">
              <span>PhishGuard</span> AI
            </div>
            <TypingText messages={BOOT_MESSAGES} durationMs={SPLASH_DURATION} />
          </motion.div>

          {/* Progress bar */}
          <ProgressBar progress={progress} />

          {/* Bottom badge */}
          <motion.div
            className="splash-badge"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8, duration: 0.6 }}
          >
            <span className="splash-badge-dot" />
            Threat Detection v2.0
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
