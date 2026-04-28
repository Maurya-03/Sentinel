// src/components/dashboard/SummaryBar.tsx

import { ScanReport } from "@/types/scan";
import { Shield, AlertTriangle, Clock, Target } from "lucide-react";
import { formatTimestamp } from "@/lib/utils";
import ScoreRing from "@/components/ui/ScoreRing";
import SeverityBadge from "@/components/ui/SeverityBadge";

interface Props { report: ScanReport }

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export default function SummaryBar({ report }: Props) {
  const { summary } = report;

  return (
    <div className="grid grid-cols-1 md:grid-cols-[auto_1fr_auto] gap-4">
      {/* ── Score ring ──────────────────────────────────── */}
      <div className="stat-card items-center justify-center min-w-[140px]">
        <ScoreRing score={summary.overall_risk_score} size={108} />
      </div>

      {/* ── Severity breakdown ──────────────────────────── */}
      <div className="stat-card gap-4">
        <div className="flex items-center justify-between">
          <span className="section-label">Severity Breakdown</span>
          <SeverityBadge severity={summary.risk_rating as any} size="sm" />
        </div>

        <div className="flex flex-col gap-2.5">
          {SEV_ORDER.map((sev) => {
            const count = summary.severity_breakdown[sev] ?? 0;
            const max   = summary.total_vulnerabilities || 1;
            const pct   = (count / max) * 100;

            const barColors: Record<string, string> = {
              CRITICAL: "bg-critical",
              HIGH:     "bg-high",
              MEDIUM:   "bg-medium",
              LOW:      "bg-low",
              INFO:     "bg-info",
            };

            return (
              <div key={sev} className="flex items-center gap-3">
                <span className="font-mono text-xs text-dim w-16 shrink-0">{sev}</span>
                <div className="flex-1 h-1.5 bg-abyss rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${barColors[sev]}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="font-mono text-xs text-bright w-4 text-right">{count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Meta info ───────────────────────────────────── */}
      <div className="stat-card gap-3 min-w-[200px]">
        <span className="section-label">Scan Details</span>

        <div className="flex flex-col gap-3 mt-1">
          <MetaRow icon={<Target size={12} />} label="Target">
            <span className="font-mono text-xs text-bright truncate max-w-[160px]">
              {report.target}
            </span>
          </MetaRow>

          <MetaRow icon={<AlertTriangle size={12} />} label="Findings">
            <span className="font-mono text-xs text-bright">
              {summary.total_vulnerabilities} vulnerabilities
            </span>
          </MetaRow>

          <MetaRow icon={<Clock size={12} />} label="Scanned">
            <span className="font-mono text-xs text-bright">
              {formatTimestamp(report.scan_timestamp)}
            </span>
          </MetaRow>

          <MetaRow icon={<Shield size={12} />} label="Engine">
            <span className="font-mono text-xs text-volt">
              SENTINEL v{report.sentinel_version}
            </span>
          </MetaRow>
        </div>
      </div>
    </div>
  );
}

function MetaRow({ icon, label, children }: {
  icon: React.ReactNode; label: string; children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-dim mt-0.5">{icon}</span>
      <div className="flex flex-col gap-0.5">
        <span className="font-mono text-[10px] text-ghost uppercase tracking-wider">{label}</span>
        {children}
      </div>
    </div>
  );
}
