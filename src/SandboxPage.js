import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { supabase } from "./supabaseClient";

const C = {
  bg: "#06080d", panel: "rgba(12,16,24,0.8)", panelBorder: "rgba(255,255,255,0.04)",
  accent: "#00e5a0", accentDim: "rgba(0,229,160,0.12)", accentBorder: "rgba(0,229,160,0.2)",
  red: "#ff4757", redDim: "rgba(255,71,87,0.12)", amber: "#ffb347",
  text: "#e0e7ef", textDim: "rgba(255,255,255,0.35)", textFaint: "rgba(255,255,255,0.15)", purple: "#a78bfa",
};

export default function SandboxPage() {
  const [searchParams] = useSearchParams();
  const simId = searchParams.get("id");
  const [simulation, setSimulation] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function trackClick() {
      if (!simId) {
        setLoading(false);
        return;
      }
      try {
        const { data, error } = await supabase
          .from("simulations")
          .select("*")
          .eq("id", simId)
          .single();

        if (data && !error) {
          setSimulation({
            templateName: data.template_name,
            preview: data.message,
            icon: data.icon,
            template: data.template_key
          });
          if (!data.clicked) {
             await supabase.from("simulations").update({ clicked: true }).eq("id", simId);
          }
        }
      } catch (err) {
        console.error("Failed to track click", err);
      }
      setLoading(false);
    }
    trackClick();
  }, [simId]);

  if (loading) {
    return (
      <div style={{ background: C.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: C.text }}>
        <p style={{ fontFamily: "'Sora', sans-serif" }}>Analysing security parameters...</p>
      </div>
    );
  }

  if (!simulation) {
     return (
       <div style={{ background: C.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: C.text }}>
         <div style={{ textAlign: "center", fontFamily: "'Sora', sans-serif" }}>
           <h1 style={{ fontSize: 24, marginBottom: 12 }}>Invalid Link</h1>
           <p style={{ color: C.textDim }}>This link appears to be broken or has expired.</p>
         </div>
       </div>
     );
  }

  return (
    <div style={{ background: C.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyItems: "center", color: C.text, fontFamily: "'Sora', sans-serif" }}>
          <div className="fixed inset-0 flex items-center justify-center p-6 fade-in" style={{ zIndex: 9999, background: "rgba(6,8,13,0.92)", backdropFilter: "blur(20px)" }}>
            <div className="fade-up" style={{
              background: "rgba(255,71,87,0.05)", border: "1px solid rgba(255,71,87,0.25)",
              borderRadius: 24, padding: "48px 40px", maxWidth: 640, width: "100%", textAlign: "left",
              boxShadow: "0 20px 60px rgba(255,71,87,0.15), inset 0 0 0 2px rgba(255,71,87,0.1)",
              position: "relative",
            }}>
              
              <div style={{ textAlign: "center", marginBottom: 36 }}>
                <div style={{ fontSize: 64, marginBottom: 16, filter: "drop-shadow(0 0 20px rgba(255,71,87,0.5))" }}>🚨</div>
                <h2 style={{ fontSize: 32, fontWeight: 800, color: C.red, letterSpacing: -1, marginBottom: 8 }}>
                  Oops! You've Been Phished.
                </h2>
                <p style={{ fontSize: 15, color: "rgba(255,255,255,0.7)", lineHeight: 1.6 }}>
                  This was a simulated phishing attack designed to test your security awareness. 
                  <br/><span style={{ color: C.red, fontWeight: 600 }}>If this were real, your data would be compromised.</span>
                </p>
              </div>

              <div style={{
                background: "rgba(0,0,0,0.6)", border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: 16, padding: "24px", marginBottom: 32,
              }}>
                <div style={{ fontSize: 10, color: C.textDim, letterSpacing: 2, fontFamily: "'Azeret Mono', monospace", marginBottom: 16 }}>ANALYZING THE ATTACK</div>
                <div style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 24 }}>
                  <div style={{ fontSize: 36, filter: "drop-shadow(0 2px 8px rgba(0,0,0,0.5))" }}>{simulation.icon}</div>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 700, color: "white", marginBottom: 6 }}>{simulation.templateName}</div>
                    <div style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", lineHeight: 1.6, fontFamily: "'Azeret Mono', monospace" }}>{simulation.preview}</div>
                  </div>
                </div>

                {simulation.template === "tata_aia" ? (
                  <div style={{ padding: "18px", background: "rgba(255,179,71,0.08)", border: "1px solid rgba(255,179,71,0.25)", borderRadius: 12 }}>
                    <div style={{ color: C.amber, fontWeight: 700, fontSize: 14, marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
                      <span>🛡️</span> TATA AIA Security Tip
                    </div>
                    <div style={{ color: "rgba(255,255,255,0.85)", fontSize: 13, lineHeight: 1.6 }}>
                      TATA AIA Life Insurance will <strong>never</strong> ask you to pay your premium through an unverified SMS link or WhatsApp message. Always use the official <strong>tataaia.com</strong> portal for policy renewals and KYC updates. Never share OTPs over the phone.
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "18px", background: "rgba(255,179,71,0.08)", border: "1px solid rgba(255,179,71,0.25)", borderRadius: 12 }}>
                    <div style={{ color: C.amber, fontWeight: 700, fontSize: 14, marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
                      <span>🛡️</span> Red Flags You Missed
                    </div>
                    <ul style={{ color: "rgba(255,255,255,0.85)", fontSize: 13, lineHeight: 1.6, paddingLeft: 22, margin: 0 }}>
                      <li style={{ marginBottom: 6 }}>Creating a false sense of extreme urgency.</li>
                      <li style={{ marginBottom: 6 }}>Requesting sensitive actions (login, payment) via direct link.</li>
                      <li>Using an unexpected or spoofed sender address.</li>
                    </ul>
                  </div>
                )}
              </div>

              <button onClick={() => navigate("/")} style={{
                width: "100%", padding: "16px", borderRadius: 12, fontSize: 15, fontWeight: 700,
                background: C.red, color: "white", border: "none", cursor: "pointer",
                boxShadow: "0 4px 20px rgba(255,71,87,0.3)", transition: "transform 0.2s",
              }} onMouseOver={e=>e.target.style.transform="translateY(-2px)"} onMouseOut={e=>e.target.style.transform="translateY(0)"}>
                I Understand, Return to Dashboard
              </button>
            </div>
          </div>
    </div>
  )
}
