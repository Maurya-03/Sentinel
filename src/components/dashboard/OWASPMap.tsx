"use client";

// src/components/dashboard/OWASPMap.tsx — OWASP Top 10 coverage heatmap

import { Vulnerability } from "@/types/scan";
import { cn } from "@/lib/utils";

interface Props { vulnerabilities: Vulnerability[] }

const OWASP_TOP10 = [
  { id: "A01", label: "Broken Access Control" },
  { id: "A02", label: "Cryptographic Failures" },
  { id: "A03", label: "Injection" },
  { id: "A04", label: "Insecure Design" },
  { id: "A05", label: "Security Misconfiguration" },
  { id: "A06", label: "Vulnerable Components" },
  { id: "A07", label: "Auth Failures" },
  { id: "A08", label: "Integrity Failures" },
  { id: "A09", label: "Logging Failures" },
  { id: "A10", label: "SSRF" },
];

export default function OWASPMap({ vulnerabilities }: Props) {
  // Build a map of OWASP ID → highest severity found
  const owaspHits: Record<string, string> = {};
  for (const v of vulnerabilities) {
    const match = v.owasp?.match(/A(\d{2}):/);
    if (!match) continue;
    const id = `A${match[1]}`;
    const current = owaspHits[id];
    // Keep highest severity
    const order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
    if (!current || order.indexOf(v.severity) < order.indexOf(current)) {
      owaspHits[id] = v.severity;
    }
  }

  const hitColors: Record<string, string> = {
    CRITICAL: "bg-critical/20 border-critical/40 text-critical",
    HIGH:     "bg-high/20    border-high/40    text-high",
    MEDIUM:   "bg-medium/20  border-medium/40  text-medium",
    LOW:      "bg-low/20     border-low/40     text-low",
    INFO:     "bg-info/20    border-info/40    text-info",
  };

  return (
    <div className="stat-card">
      <span className="section-label mb-1">OWASP Top 10 Coverage</span>

      <div className="grid grid-cols-5 gap-2">
        {OWASP_TOP10.map(({ id, label }) => {
          const sev     = owaspHits[id];
          const classes = sev ? hitColors[sev] : "bg-abyss border-border text-ghost";

          return (
            <div
              key={id}
              className={cn(
                "rounded-lg border px-2 py-2.5 flex flex-col gap-1 transition-all",
                classes
              )}
              title={label}
            >
              <span className="font-mono text-[11px] font-500">{id}:2021</span>
              <span className="font-body text-[10px] leading-tight opacity-80 line-clamp-2">
                {label}
              </span>
              {sev && (
                <span className="font-mono text-[9px] mt-auto opacity-70 uppercase">{sev}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
