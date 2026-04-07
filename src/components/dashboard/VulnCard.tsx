"use client";

// src/components/dashboard/VulnCard.tsx

import { useState } from "react";
import {
  ChevronDown, ChevronRight, ExternalLink, Shield,
  Zap, Database, Globe, Lock, Info
} from "lucide-react";
import { Vulnerability } from "@/types/scan";
import { cn, SEVERITY_CONFIG, getVulnIcon } from "@/lib/utils";
import SeverityBadge from "@/components/ui/SeverityBadge";

interface Props {
  vuln:  Vulnerability;
  index: number;
}

function VulnTypeIcon({ type }: { type: string }) {
  if (type.includes("SQL"))    return <Database size={13} className="text-flaw" />;
  if (type.includes("XSS"))    return <Zap       size={13} className="text-breach" />;
  if (type.includes("Port"))   return <Globe     size={13} className="text-pulse" />;
  if (type.includes("Header")) return <Lock      size={13} className="text-medium" />;
  return                              <Info      size={13} className="text-dim" />;
}

export default function VulnCard({ vuln, index }: Props) {
  const [open, setOpen] = useState(index < 2); // first two expanded by default
  const cfg = SEVERITY_CONFIG[vuln.severity] ?? SEVERITY_CONFIG.INFO;
  const ai  = vuln.ai_analysis;

  return (
    <div
      className={cn(
        "glass rounded-xl overflow-hidden transition-all duration-200",
        "border", cfg.border,
        open && cfg.glow,
      )}
    >
      {/* ── Header row ─────────────────────────────────────────────────── */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-overlay/40 transition-colors text-left"
      >
        {/* Index badge */}
        <span className="font-mono text-xs text-ghost w-6 shrink-0 select-none">
          {String(index + 1).padStart(2, "0")}
        </span>

        {/* Type icon */}
        <span className="shrink-0">
          <VulnTypeIcon type={vuln.type} />
        </span>

        {/* Title + URL */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-display font-600 text-sm text-white">
              {vuln.type}
              {vuln.subtype ? <span className="text-dim font-400"> · {vuln.subtype}</span> : null}
            </span>
            {vuln.port && (
              <span className="font-mono text-xs text-pulse">
                :{vuln.port} {vuln.service}
              </span>
            )}
            {vuln.header && (
              <span className="font-mono text-xs text-dim">
                {vuln.header}
              </span>
            )}
          </div>
          <p className="font-mono text-xs text-ghost truncate mt-0.5">
            {vuln.url}
            {vuln.param && <span className="text-dim"> ?{vuln.param}=</span>}
          </p>
        </div>

        {/* Right-side badges */}
        <div className="flex items-center gap-3 shrink-0 ml-2">
          {/* CVSS score */}
          <div className={cn("font-mono text-xs px-2 py-1 rounded", cfg.bg, cfg.color)}>
            {vuln.numeric_score.toFixed(1)}
          </div>

          <SeverityBadge severity={vuln.severity} size="sm" />

          {/* Confidence */}
          <span className="font-mono text-[10px] text-ghost hidden md:inline">
            {ai.confidence}
          </span>

          {/* Expand chevron */}
          <span className="text-dim">
            {open
              ? <ChevronDown size={14} />
              : <ChevronRight size={14} />
            }
          </span>
        </div>
      </button>

      {/* ── Expanded body ──────────────────────────────────────────────── */}
      {open && (
        <div className="border-t border-border/60 px-5 pb-5 pt-4 animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Left col — technical details */}
            <div className="flex flex-col gap-4">
              {/* Evidence */}
              <Section label="Evidence">
                <code className="block bg-abyss border border-border rounded-lg px-4 py-3
                                 font-mono text-xs text-soft leading-relaxed whitespace-pre-wrap break-all">
                  {vuln.evidence}
                </code>
              </Section>

              {/* Payload */}
              {vuln.payload && (
                <Section label="Payload Used">
                  <code className="block bg-abyss border border-flaw/20 rounded-lg px-4 py-2.5
                                   font-mono text-xs text-flaw leading-relaxed">
                    {vuln.payload}
                  </code>
                </Section>
              )}

              {/* Classification */}
              <Section label="Classification">
                <div className="flex flex-wrap gap-2">
                  {vuln.cwe !== "N/A" && (
                    <Tag label={vuln.cwe} href={`https://cwe.mitre.org/data/definitions/${vuln.cwe.replace("CWE-","")}.html`} />
                  )}
                  {vuln.owasp !== "N/A" && (
                    <Tag label={vuln.owasp} />
                  )}
                  {vuln.method && <Tag label={`METHOD: ${vuln.method}`} />}
                  {vuln.param  && <Tag label={`PARAM: ${vuln.param}`} />}
                </div>
              </Section>
            </div>

            {/* Right col — AI analysis */}
            <div className="flex flex-col gap-4">
              {/* AI source badge */}
              <div className="flex items-center gap-2">
                <span className="section-label">AI Analysis</span>
                <span className={cn(
                  "font-mono text-[10px] px-2 py-0.5 rounded border",
                  ai.source === "llm+kb"
                    ? "text-volt border-volt/30 bg-volt/10"
                    : "text-pulse border-pulse/30 bg-pulse/10"
                )}>
                  {ai.source === "llm+kb" ? "LLM + KB" : "Rule-Based"}
                </span>
                <span className="font-mono text-[10px] text-ghost ml-auto">
                  Confidence: {ai.confidence}
                </span>
              </div>

              <Section label="Why It Exists">
                <p className="font-body text-sm text-soft leading-relaxed">
                  {ai.explanation}
                </p>
              </Section>

              <Section label="Impact">
                <p className={cn("font-body text-sm leading-relaxed", cfg.color)}>
                  {ai.impact}
                </p>
              </Section>

              <Section label="Mitigation Steps">
                <ol className="flex flex-col gap-2">
                  {ai.mitigation.map((step, i) => (
                    <li key={i} className="flex gap-3">
                      <span className="font-mono text-xs text-volt mt-0.5 shrink-0">
                        {String(i + 1).padStart(2, "0")}
                      </span>
                      <span className="font-body text-xs text-soft leading-relaxed">
                        {step}
                      </span>
                    </li>
                  ))}
                </ol>
              </Section>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <span className="section-label">{label}</span>
      {children}
    </div>
  );
}

function Tag({ label, href }: { label: string; href?: string }) {
  const cls = "inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[10px] text-dim bg-abyss border border-border hover:border-muted transition-colors";
  if (href) {
    return (
      <a href={href} target="_blank" className={cls}>
        {label}
        <ExternalLink size={9} />
      </a>
    );
  }
  return <span className={cls}>{label}</span>;
}
